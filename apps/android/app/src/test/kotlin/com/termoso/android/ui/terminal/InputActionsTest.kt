package com.termoso.android.ui.terminal

import android.view.KeyEvent
import com.termoso.android.ResourceTest
import com.termoso.core.KeyGroup
import com.termoso.core.PanelKeyDef
import com.termoso.core.SpecialKey
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class InputActionsTest : ResourceTest() {
    @Test
    fun parsesSpecialKeysWithModifiers() {
        val k = KeyActions.parse("ctrl+shift+key:tab") as PanelKey.Special
        assertEquals(SpecialKey.TAB, k.key)
        assertTrue(k.mods.ctrl && k.mods.shift && !k.mods.alt)
        assertEquals("^shift+tab", k.label)
        assertEquals("ctrl+shift+key:TAB", KeyActions.encode(k))
    }

    @Test
    fun parsesTextAndStickyModifiers() {
        val pipe = KeyActions.parse("text:|") as PanelKey.Text
        assertEquals("|", pipe.text)
        assertEquals("|", pipe.label)
        val ctrlC = KeyActions.parse("ctrl+text:c") as PanelKey.Text
        assertEquals("^C", ctrlC.label)
        assertEquals("Ctrl+C", KeyActions.describe(ctrlC))
        val alt = KeyActions.parse("mod:alt") as PanelKey.Modifier
        assertEquals(StickyMod.ALT, alt.which)
        assertEquals("mod:alt", KeyActions.encode(alt))
    }

    @Test
    fun customLabelWins() {
        assertEquals("Quit", KeyActions.parse(PanelKeyDef(label = "Quit", action = "ctrl+text:c"))?.label)
        assertEquals("^C", KeyActions.parse(PanelKeyDef(label = "  ", action = "ctrl+text:c"))?.label)
    }

    @Test
    fun rejectsUnknownOrUnsafeActions() {
        assertNull(KeyActions.parse(""))
        assertNull(KeyActions.parse("key:NOPE"))
        assertNull(KeyActions.parse("shell:rm -rf /"))
        assertNull(KeyActions.parse("text:"))
        assertNull(KeyActions.parse("ctrl+text:ab"))
        assertNull(KeyActions.parse("mod:meta"))
        assertNull(KeyActions.parse("F5"))
    }

    @Test
    fun roundTripsEveryPaletteEntryAndDefaultGroup() {
        for (key in KeyGroups.palette) {
            assertEquals(key, KeyActions.parse(KeyActions.toDef(key)))
        }
        for (g in KeyGroups.defaults) {
            for (def in g.keys) assertTrue(def.action, KeyActions.parse(def) != null)
        }
    }

    @Test
    fun defaultRowsMatchTheFormerStaticPanel() {
        val rows = KeyGroups.rows(emptyList())
        assertEquals(8, rows.size)
        assertEquals(listOf("shift+tab", "esc", "ctrl", "←", "↑", "↓", "→"), rows[0].map { it.label })
        assertTrue(rows[1].all { it.label.startsWith("ctrl+B") })
        assertEquals(listOf("F9", "F10", "F11", "F12"), rows[7].map { it.label })
        assertEquals(KeyGroups.defaults, KeyGroups.editable(emptyList()))
    }

    @Test
    fun brokenKeysAreSkippedNotFatal() {
        val stored = listOf(
            KeyGroup("a", "Mine", listOf(PanelKeyDef("x", "key:BOGUS"), PanelKeyDef("", "key:ESCAPE")), enabled = true),
            KeyGroup("b", "Off", listOf(PanelKeyDef("", "key:F5")), enabled = false),
            KeyGroup("c", "Empty", listOf(PanelKeyDef("", "nonsense")), enabled = true),
        )
        val rows = KeyGroups.rows(stored)
        assertEquals(1, rows.size)
        assertEquals(listOf("esc"), rows[0].map { it.label })
        assertEquals(stored, KeyGroups.editable(stored))
    }

    @Test
    fun newGroupIdsNeverCollide() {
        val existing = listOf(KeyGroup("custom1", "", emptyList(), true), KeyGroup("custom2", "", emptyList(), true))
        val id = KeyGroups.newGroupId(existing)
        assertFalse(existing.any { it.id == id })
        assertEquals("custom3", id)
    }

    @Test
    fun inputActionGrammar() {
        assertEquals(InputAction.Disabled, InputAction.parse(""))
        assertEquals(InputAction.Disabled, InputAction.parse("disabled"))
        assertEquals(InputAction.Disabled, InputAction.parse("garbage"))
        assertEquals(InputAction.Ui(UiAction.FONT_UP), InputAction.parse("font_up"))
        assertEquals("scroll_down", InputAction.encode(InputAction.Ui(UiAction.SCROLL_DOWN)))
        val esc = InputAction.parse("key:ESCAPE") as InputAction.Key
        assertEquals("esc", InputAction.title(esc))
        assertEquals("key:ESCAPE", InputAction.encode(esc))
        assertEquals(InputAction.Disabled, InputAction.choices.first())
        assertEquals(InputAction.choices.size, InputAction.choices.distinct().size)
    }

    @Test
    fun volumeKeysStayVolumeKeysUnlessBound() {
        assertNull(HardwareKeys.volumeAction(KeyEvent.KEYCODE_VOLUME_UP, "", ""))
        assertNull(HardwareKeys.volumeAction(KeyEvent.KEYCODE_VOLUME_DOWN, "key:UP", "disabled"))
        assertNull(HardwareKeys.volumeAction(KeyEvent.KEYCODE_A, "key:UP", "key:DOWN"))
        assertEquals(InputAction.Ui(UiAction.SCROLL_UP), HardwareKeys.volumeAction(KeyEvent.KEYCODE_VOLUME_UP, "scroll_up", ""))
        val down = HardwareKeys.volumeAction(KeyEvent.KEYCODE_VOLUME_DOWN, "", "key:BACKSPACE") as InputAction.Key
        assertEquals(SpecialKey.BACKSPACE, (down.key as PanelKey.Special).key)
    }

    @Test
    fun hotkeysFollowTheMode() {
        val ctrlShift = "ctrl_shift"
        assertEquals(Hotkey.NEXT_SESSION, HardwareKeys.hotkey(KeyEvent.KEYCODE_DPAD_RIGHT, ctrl = true, shift = true, alt = false, mode = ctrlShift))
        assertNull(HardwareKeys.hotkey(KeyEvent.KEYCODE_DPAD_RIGHT, ctrl = true, shift = false, alt = false, mode = ctrlShift))
        assertEquals(Hotkey.PREV_SESSION, HardwareKeys.hotkey(KeyEvent.KEYCODE_DPAD_LEFT, ctrl = true, shift = false, alt = false, mode = "ctrl"))
        assertEquals(Hotkey.FONT_UP, HardwareKeys.hotkey(KeyEvent.KEYCODE_EQUALS, ctrl = true, shift = true, alt = false, mode = "ctrl"))
        assertEquals(Hotkey.PASTE, HardwareKeys.hotkey(KeyEvent.KEYCODE_V, ctrl = true, shift = true, alt = false, mode = ctrlShift))
        assertEquals(Hotkey.TOGGLE_PANEL, HardwareKeys.hotkey(KeyEvent.KEYCODE_K, ctrl = true, shift = true, alt = false, mode = "ctrl"))
        // Plain Ctrl+C / Ctrl+W must reach the shell.
        assertNull(HardwareKeys.hotkey(KeyEvent.KEYCODE_C, ctrl = true, shift = false, alt = false, mode = ctrlShift))
        assertNull(HardwareKeys.hotkey(KeyEvent.KEYCODE_W, ctrl = true, shift = false, alt = false, mode = ctrlShift))
        // Alt chords and modifier-only / unmodified keys are never hotkeys.
        assertNull(HardwareKeys.hotkey(KeyEvent.KEYCODE_W, ctrl = true, shift = true, alt = true, mode = ctrlShift))
        assertNull(HardwareKeys.hotkey(KeyEvent.KEYCODE_CTRL_LEFT, ctrl = true, shift = false, alt = false, mode = "ctrl"))
        assertNull(HardwareKeys.hotkey(KeyEvent.KEYCODE_W, ctrl = false, shift = true, alt = false, mode = ctrlShift))
        // Disabled lets everything through, including paste and the panel toggle.
        assertNull(HardwareKeys.hotkey(KeyEvent.KEYCODE_V, ctrl = true, shift = true, alt = false, mode = "disabled"))
        assertNull(HardwareKeys.hotkey(KeyEvent.KEYCODE_W, ctrl = true, shift = true, alt = false, mode = "disabled"))
    }

    @Test
    fun sessionNeighbourWraps() {
        assertEquals(1, HardwareKeys.neighbour(3, 0, forward = true))
        assertEquals(0, HardwareKeys.neighbour(3, 2, forward = true))
        assertEquals(2, HardwareKeys.neighbour(3, 0, forward = false))
        assertNull(HardwareKeys.neighbour(1, 0, forward = true))
        assertNull(HardwareKeys.neighbour(3, -1, forward = true))
    }

    @Test
    fun gesturesDefaultOn() {
        val g = TerminalGestures()
        assertTrue(g.pinchZoom && g.swipeArrows && g.swipeSessions)
    }
}

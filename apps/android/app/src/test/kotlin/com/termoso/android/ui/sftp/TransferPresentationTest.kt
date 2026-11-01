package com.termoso.android.ui.sftp

import com.termoso.android.ResourceTest
import com.termoso.core.TransferCard
import com.termoso.core.TransferDirection
import com.termoso.core.TransferStatus
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TransferPresentationTest : ResourceTest() {
    private fun card(status: TransferStatus, done: ULong = 0uL, total: ULong? = 2048uL, rate: ULong = 0uL) = TransferCard(
        id = 1uL,
        direction = TransferDirection.DOWNLOAD,
        name = "big.bin",
        remotePath = "/srv/big.bin",
        localPath = "/cache/dl-1/big.bin",
        done = done,
        total = total,
        bytesPerSec = rate,
        status = status,
        toSession = null,
    )

    @Test
    fun actionsFollowTheQueueState() {
        assertEquals(listOf(TransferAction.Pause, TransferAction.Cancel), TransferStatus.Queued.actions)
        assertEquals(listOf(TransferAction.Pause, TransferAction.Cancel), TransferStatus.Running.actions)
        assertEquals(listOf(TransferAction.Resume, TransferAction.Cancel), TransferStatus.Paused.actions)
        assertEquals(listOf(TransferAction.Retry, TransferAction.Dismiss), TransferStatus.Failed("eof").actions)
        assertEquals(listOf(TransferAction.Dismiss), TransferStatus.Done.actions)
        assertEquals(listOf(TransferAction.Dismiss), TransferStatus.Cancelled.actions)
    }

    @Test
    fun onlyFinalStatesAreFinished() {
        assertFalse(TransferStatus.Queued.isFinished)
        assertFalse(TransferStatus.Running.isFinished)
        assertFalse(TransferStatus.Paused.isFinished)
        assertTrue(TransferStatus.Failed("eof").isFinished)
        assertTrue(TransferStatus.Done.isFinished)
        assertTrue(TransferStatus.Cancelled.isFinished)
    }

    @Test
    fun progressBarStaysWhilePaused() {
        assertTrue(TransferStatus.Running.showsProgress)
        assertTrue(TransferStatus.Paused.showsProgress)
        assertFalse(TransferStatus.Failed("eof").showsProgress)
        assertFalse(TransferStatus.Done.showsProgress)
    }

    @Test
    fun labelsKeepPartialProgressVisible() {
        assertEquals("Queued", card(TransferStatus.Queued).statusLabel())
        assertEquals("Queued · 1.0 KB / 2.0 KB", card(TransferStatus.Queued, done = 1024uL).statusLabel())
        assertEquals("1.0 KB / 2.0 KB · 512 B/s", card(TransferStatus.Running, done = 1024uL, rate = 512uL).statusLabel())
        assertEquals("1.0 KB", card(TransferStatus.Running, done = 1024uL, total = null).statusLabel())
        assertEquals("Paused · 1.0 KB / 2.0 KB", card(TransferStatus.Paused, done = 1024uL).statusLabel())
        assertEquals("Done · 2.0 KB", card(TransferStatus.Done, done = 2048uL).statusLabel())
        assertEquals("Connection lost", card(TransferStatus.Failed("Connection lost")).statusLabel())
        assertEquals("Connection lost · 1.0 KB / 2.0 KB", card(TransferStatus.Failed("Connection lost"), done = 1024uL).statusLabel())
        assertEquals("Cancelled", card(TransferStatus.Cancelled, done = 1024uL).statusLabel())
    }
}

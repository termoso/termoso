import { useEffect } from "react";
import { useColorScheme } from "@mui/material";
import { useColorSchemes, useSettings } from "@/ipc/hooks";
import { setLanguage } from "@/i18n";
import { applyTerminalScheme, applyTerminalSettings } from "@/terminal/store";
import { setCustomThemes } from "@/terminal/themes";
import { applyNotificationSettings } from "./notifications";
import { applyTraySettings } from "./tray";
import { applyTriggers } from "@/terminal/store";

/** Keeps MUI's color scheme, the UI language and the terminals in step with the settings stored by Rust. */
export function ThemeModeSync() {
  const { setMode, mode, systemMode } = useColorScheme();
  const { data } = useSettings();
  useEffect(() => {
    if (data) {
      setMode(data.theme);
      setLanguage(data.language);
      applyTerminalSettings(data);
      applyNotificationSettings(data);
      applyTriggers(data.triggers);
      applyTraySettings(data);
    }
  }, [data, setMode]);
  const schemes = useColorSchemes(null);
  useEffect(() => {
    // User colour schemes live in the vault; re-resolve every pane when they change.
    if (schemes.data) setCustomThemes(schemes.data);
    const resolved = mode === "system" ? systemMode : mode;
    applyTerminalScheme(resolved === "light" ? "light" : "dark");
  }, [schemes.data, mode, systemMode]);
  return null;
}

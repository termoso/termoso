import { Box, Button, IconButton, Switch, TextField, Tooltip, Typography } from "@mui/material";
import AddRoundedIcon from "@mui/icons-material/AddRounded";
import DeleteOutlineRoundedIcon from "@mui/icons-material/DeleteOutlineRounded";
import { SectionCard } from "@/components/ui";
import type { Settings, Trigger } from "@/ipc/types";
import { monoFontFamily } from "@/theme/theme";
import { tr } from "@/i18n";

const validRegex = (p: string) => {
  try {
    new RegExp(p, "m");
    return true;
  } catch {
    return false;
  }
};

/** Output triggers: regex → highlight / notification / typed reply, for every terminal. */
export function TriggersCard({
  s,
  update,
}: {
  s: Settings;
  update: (patch: Partial<Settings>) => void;
}) {
  const list = s.triggers;
  const patch = (id: string, p: Partial<Trigger>) =>
    update({ triggers: list.map((t) => (t.id === id ? { ...t, ...p } : t)) });
  const add = () =>
    update({
      triggers: [
        ...list,
        {
          id: crypto.randomUUID(),
          name: "",
          pattern: "",
          enabled: true,
          notify: true,
          highlight: true,
          reply: null,
        },
      ],
    });
  return (
    <SectionCard title={tr("Triggers")}>
      <Typography variant="body2" color="text.secondary">
        {tr(
          "Regular expressions watched on the output of every session. A match can highlight the line, show a notification and type a reply (use \\n for Enter). Each trigger fires at most once every two seconds per tab.",
        )}
      </Typography>
      {list.map((t) => (
        <Box
          key={t.id}
          sx={{
            display: "grid",
            gridTemplateColumns: "auto 1fr 1fr",
            gap: 1,
            alignItems: "center",
            p: 1,
            borderRadius: 2,
            bgcolor: "surface.high",
          }}
        >
          <Switch
            size="small"
            checked={t.enabled}
            onChange={(e) => patch(t.id, { enabled: e.target.checked })}
          />
          <TextField
            size="small"
            label={tr("Name")}
            value={t.name}
            onChange={(e) => patch(t.id, { name: e.target.value })}
          />
          <Box sx={{ display: "flex", gap: 0.5, alignItems: "center" }}>
            <TextField
              size="small"
              label={tr("Regex")}
              value={t.pattern}
              error={t.pattern !== "" && !validRegex(t.pattern)}
              onChange={(e) => patch(t.id, { pattern: e.target.value })}
              slotProps={{ input: { sx: { fontFamily: monoFontFamily } } }}
              sx={{ flex: 1 }}
            />
            <Tooltip title={tr("Remove")}>
              <IconButton
                size="small"
                onClick={() => update({ triggers: list.filter((x) => x.id !== t.id) })}
              >
                <DeleteOutlineRoundedIcon fontSize="small" />
              </IconButton>
            </Tooltip>
          </Box>
          <Box />
          <Box sx={{ display: "flex", gap: 2, alignItems: "center" }}>
            <Typography variant="body2" sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
              <Switch
                size="small"
                checked={t.highlight}
                onChange={(e) => patch(t.id, { highlight: e.target.checked })}
              />
              {tr("Highlight")}
            </Typography>
            <Typography variant="body2" sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
              <Switch
                size="small"
                checked={t.notify}
                onChange={(e) => patch(t.id, { notify: e.target.checked })}
              />
              {tr("Notify")}
            </Typography>
          </Box>
          <TextField
            size="small"
            label={tr("Reply (optional)")}
            value={t.reply ?? ""}
            onChange={(e) => patch(t.id, { reply: e.target.value === "" ? null : e.target.value })}
            slotProps={{ input: { sx: { fontFamily: monoFontFamily } } }}
          />
        </Box>
      ))}
      <Button size="small" startIcon={<AddRoundedIcon />} onClick={add} sx={{ alignSelf: "flex-start" }}>
        {tr("Add trigger")}
      </Button>
    </SectionCard>
  );
}

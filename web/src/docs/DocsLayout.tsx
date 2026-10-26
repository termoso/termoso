import { useCallback, useState } from "react";
import {
  Box,
  Button,
  Container,
  Drawer,
  IconButton,
  List,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Typography,
} from "@mui/material";
import MenuRoundedIcon from "@mui/icons-material/MenuRounded";
import SearchRoundedIcon from "@mui/icons-material/SearchRounded";
import GitHubIcon from "@mui/icons-material/GitHub";
import { Link as RouterLink, NavLink, Outlet } from "react-router";
import { Logo } from "@/components/Logo";
import { ThemeToggle } from "@/layout/ThemeToggle";
import { useAuthState } from "@/auth/store";
import { CabinetButton } from "@/pages/landing/Shell";
import { hrefOf, sections } from "./manifest";
import { DocsSearch, useSearchShortcut } from "./DocsSearch";

export const DOCS_HEADER = 60;
export const REPO = "https://github.com/termoso/termoso";
const SIDEBAR = 264;

function Sidebar({ onNavigate }: { onNavigate?: () => void }) {
  return (
    <Box component="nav" aria-label="Documentation" sx={{ py: 2 }}>
      {sections.map((s) => (
        <Box key={s.title} sx={{ mb: 2.5 }}>
          <Typography
            variant="overline"
            component="div"
            sx={{ px: 2, mb: 0.5, color: "text.secondary", letterSpacing: "0.08em" }}
          >
            {s.title}
          </Typography>
          <List dense disablePadding>
            {s.pages.map((p) => (
              <ListItemButton
                key={p.path}
                component={NavLink}
                to={hrefOf(p)}
                end
                onClick={onNavigate}
                sx={{
                  mx: 1,
                  borderRadius: 1.5,
                  minHeight: 34,
                  color: "text.secondary",
                  "&.active": {
                    color: "primary.main",
                    bgcolor: "action.selected",
                    "& .MuiListItemIcon-root": { color: "primary.main" },
                  },
                }}
              >
                <ListItemIcon sx={{ minWidth: 30, color: "inherit", "& svg": { fontSize: 18 } }}>
                  {p.icon}
                </ListItemIcon>
                <ListItemText
                  primary={p.title}
                  slotProps={{ primary: { variant: "body2", sx: { fontWeight: 500 } } }}
                />
              </ListItemButton>
            ))}
          </List>
        </Box>
      ))}
    </Box>
  );
}

export function DocsLayout() {
  const { session } = useAuthState();
  const [drawer, setDrawer] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  const openSearch = useCallback(() => setSearchOpen(true), []);
  useSearchShortcut(openSearch);

  return (
    <Box sx={{ minHeight: "100vh", bgcolor: "surface.lowest", overflowX: "clip" }}>
      <Box
        component="header"
        sx={{
          position: "sticky",
          top: 0,
          zIndex: 10,
          bgcolor: "color-mix(in srgb, var(--mui-palette-surface-lowest) 86%, transparent)",
          backdropFilter: "blur(12px)",
          borderBottom: 1,
          borderColor: "border.light",
        }}
      >
        <Container
          maxWidth="xl"
          sx={{ height: DOCS_HEADER, display: "flex", alignItems: "center", gap: 1 }}
        >
          <IconButton
            aria-label="Open navigation"
            onClick={() => setDrawer(true)}
            sx={{ display: { md: "none" }, mr: 0.5 }}
          >
            <MenuRoundedIcon />
          </IconButton>
          <Box
            component={RouterLink}
            to="/docs"
            sx={{
              display: "flex",
              alignItems: "center",
              gap: 1,
              textDecoration: "none",
              color: "inherit",
            }}
          >
            <Logo size={26} />
            <Typography
              variant="h6"
              component="span"
              sx={{
                fontWeight: 500,
                color: "text.secondary",
                letterSpacing: "-0.01em",
                lineHeight: 1,
              }}
            >
              docs
            </Typography>
          </Box>
          <Box sx={{ flex: 1 }} />
          <Button
            onClick={openSearch}
            variant="outlined"
            color="inherit"
            startIcon={<SearchRoundedIcon />}
            sx={{
              display: { xs: "none", sm: "inline-flex" },
              color: "text.secondary",
              borderColor: "border.basic",
              width: 260,
              justifyContent: "flex-start",
              fontWeight: 400,
              "& kbd": {
                ml: "auto",
                px: 0.75,
                borderRadius: 1,
                border: 1,
                borderColor: "border.basic",
                fontSize: 11,
                fontFamily: "inherit",
              },
            }}
          >
            Search
            <Box component="kbd">Ctrl K</Box>
          </Button>
          <IconButton aria-label="Search" onClick={openSearch} sx={{ display: { sm: "none" } }}>
            <SearchRoundedIcon />
          </IconButton>
          <Button
            component={RouterLink}
            to="/"
            variant="text"
            sx={{ color: "text.secondary", display: { xs: "none", md: "inline-flex" } }}
          >
            Website
          </Button>
          <IconButton
            component="a"
            href={REPO}
            target="_blank"
            rel="noreferrer"
            aria-label="GitHub"
            sx={{ color: "text.secondary" }}
          >
            <GitHubIcon />
          </IconButton>
          <ThemeToggle />
          <CabinetButton
            to={session ? "/account" : "/login"}
            variant="contained"
            sx={{ ml: 1, display: { xs: "none", sm: "inline-flex" } }}
          >
            {session ? "Open cabinet" : "Sign in"}
          </CabinetButton>
        </Container>
      </Box>

      <Container maxWidth="xl" sx={{ display: "flex", alignItems: "flex-start" }}>
        <Box
          component="aside"
          sx={{
            width: SIDEBAR,
            flexShrink: 0,
            position: "sticky",
            top: DOCS_HEADER,
            maxHeight: `calc(100vh - ${DOCS_HEADER}px)`,
            overflowY: "auto",
            borderRight: 1,
            borderColor: "border.light",
            display: { xs: "none", md: "block" },
          }}
        >
          <Sidebar />
        </Box>
        <Box component="main" sx={{ flex: 1, minWidth: 0 }}>
          <Outlet />
        </Box>
      </Container>

      <Drawer
        open={drawer}
        onClose={() => setDrawer(false)}
        slotProps={{ paper: { sx: { width: SIDEBAR } } }}
      >
        <Box sx={{ px: 2, height: DOCS_HEADER, display: "flex", alignItems: "center" }}>
          <Logo size={24} />
        </Box>
        <Sidebar onNavigate={() => setDrawer(false)} />
      </Drawer>

      {searchOpen && <DocsSearch open onClose={() => setSearchOpen(false)} />}
    </Box>
  );
}

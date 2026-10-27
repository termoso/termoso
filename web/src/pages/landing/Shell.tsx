import { useState, type ReactNode } from "react";
import {
  Box,
  Button,
  type ButtonProps,
  Container,
  Divider,
  Drawer,
  IconButton,
  Link,
  List,
  ListItemButton,
  ListItemText,
  Stack,
  Typography,
} from "@mui/material";
import MenuRoundedIcon from "@mui/icons-material/MenuRounded";
import CloseRoundedIcon from "@mui/icons-material/CloseRounded";
import { Link as RouterLink } from "react-router";

import { Logo } from "@/components/Logo";
import { ThemeToggle } from "@/layout/ThemeToggle";
import { useAuthState } from "@/auth/store";
import { useServerInfo } from "@/api/hooks";

export const REPO = "https://github.com/termoso/termoso";
export const RELEASES = `${REPO}/releases/latest`;
export const README = `${REPO}#readme`;
export const SELF_HOSTING = `${REPO}/blob/main/docs/SELF_HOSTING.md`;
export const IOS_SIDELOAD = `${REPO}/blob/main/docs/IOS_SIDELOAD.md`;

export const HEADER = 60;

const origin = (u: string) => u.replace(/\/+$/, "");

/** Button that points into the cabinet; on a landing-only or dedicated docs
 *  host it links to the cabinet origin (the SPA there has no session, and a
 *  client-side `/login` would render on the wrong origin). */
export function CabinetButton({
  to,
  ...props
}: Pick<ButtonProps, "variant" | "size" | "sx" | "endIcon" | "children"> & { to: string }) {
  const info = useServerInfo().data;
  const docsHost = !!info?.docs_url && origin(info.docs_url) === window.location.origin;
  if (info?.web_url && (info.landing_only || docsHost)) {
    return <Button {...props} href={`${origin(info.web_url)}${to}`} />;
  }
  return <Button {...props} component={RouterLink} to={to} />;
}

export function SectionTitle({
  eyebrow,
  title,
  text,
  center,
}: {
  eyebrow?: string;
  title: string;
  text?: string;
  center?: boolean;
}) {
  return (
    <Box
      sx={{
        maxWidth: 620,
        mb: { xs: 4, md: 6 },
        mx: center ? "auto" : 0,
        textAlign: center ? "center" : "left",
      }}
    >
      {eyebrow && (
        <Typography
          variant="overline"
          component="div"
          color="primary.main"
          sx={{ mb: 1.25, letterSpacing: "0.1em" }}
        >
          {eyebrow}
        </Typography>
      )}
      <Typography
        variant="h2"
        component="h2"
        sx={{ fontSize: { xs: "1.75rem", md: "2.25rem" }, letterSpacing: "-0.02em" }}
      >
        {title}
      </Typography>
      {text && (
        <Typography
          variant="body1"
          color="text.secondary"
          sx={{ mt: 1.75, fontSize: "1.0625rem", lineHeight: 1.6 }}
        >
          {text}
        </Typography>
      )}
    </Box>
  );
}

export function Section({
  id,
  children,
  sx,
}: {
  id?: string;
  children: ReactNode;
  sx?: Record<string, unknown>;
}) {
  return (
    <Box id={id} component="section" sx={{ py: { xs: 8, md: 12 }, scrollMarginTop: HEADER, ...sx }}>
      {children}
    </Box>
  );
}

export function Card({ children, sx }: { children: ReactNode; sx?: Record<string, unknown> }) {
  return (
    <Box
      sx={{
        bgcolor: "surface.base",
        borderRadius: 3,
        p: { xs: 3, md: 3.5 },
        border: 1,
        borderColor: "border.light",
        ...sx,
      }}
    >
      {children}
    </Box>
  );
}

/** Sticky site header shared by the landing and the public pages (/sponsor). */
export function LandingHeader() {
  const { session } = useAuthState();
  const info = useServerInfo();
  const registrationOpen = info.data?.registration_open !== false;
  const [menuOpen, setMenuOpen] = useState(false);
  return (
    <>
      <Box
        component="header"
        sx={{
          position: "sticky",
          top: 0,
          zIndex: 10,
          bgcolor: "color-mix(in srgb, var(--mui-palette-surface-lowest) 82%, transparent)",
          backdropFilter: "blur(12px)",
          borderBottom: 1,
          borderColor: "border.light",
        }}
      >
        <Container
          maxWidth="lg"
          sx={{ height: HEADER, display: "flex", alignItems: "center", gap: 1 }}
        >
          <Logo size={26} />
          <Stack direction="row" spacing={0.5} sx={{ ml: 5, display: { xs: "none", md: "flex" } }}>
            {[
              ["Product", "/#product"],
              ["Security", "/#security"],
              ["Self-hosting", "/#self-hosting"],
              ["Download", "/#download"],
              ["FAQ", "/#faq"],
            ].map(([label, href]) => (
              <Button key={href} href={href} variant="text" sx={{ color: "text.secondary" }}>
                {label}
              </Button>
            ))}
            {info.data?.docs !== false &&
              (info.data?.docs_url ? (
                <Button href={info.data.docs_url} variant="text" sx={{ color: "text.secondary" }}>
                  Docs
                </Button>
              ) : (
                <Button
                  component={RouterLink}
                  to="/docs"
                  variant="text"
                  sx={{ color: "text.secondary" }}
                >
                  Docs
                </Button>
              ))}
            <Button
              href={REPO}
              target="_blank"
              rel="noreferrer"
              variant="text"
              sx={{ color: "text.secondary" }}
            >
              GitHub
            </Button>
          </Stack>
          <Box sx={{ flex: 1 }} />
          <ThemeToggle />
          <IconButton
            aria-label="Open menu"
            onClick={() => setMenuOpen(true)}
            sx={{ ml: 0.5, display: { xs: "inline-flex", md: "none" } }}
          >
            <MenuRoundedIcon />
          </IconButton>
          {session ? (
            <CabinetButton to="/account" variant="contained" sx={{ ml: 1 }}>
              Open cabinet
            </CabinetButton>
          ) : (
            <>
              <CabinetButton to="/login" variant="text" sx={{ ml: 1 }}>
                Log in
              </CabinetButton>
              {registrationOpen && (
                <CabinetButton
                  to="/signup"
                  variant="contained"
                  sx={{ display: { xs: "none", sm: "inline-flex" } }}
                >
                  Sign up
                </CabinetButton>
              )}
            </>
          )}
        </Container>
      </Box>

      <Drawer anchor="right" open={menuOpen} onClose={() => setMenuOpen(false)}>
        <Box sx={{ width: 280, pt: 1 }} role="navigation">
          <Box sx={{ display: "flex", alignItems: "center", px: 2, py: 1 }}>
            <Logo size={24} />
            <Box sx={{ flex: 1 }} />
            <IconButton aria-label="Close menu" onClick={() => setMenuOpen(false)}>
              <CloseRoundedIcon />
            </IconButton>
          </Box>
          <List>
            {[
              ["Product", "/#product"],
              ["Security", "/#security"],
              ["Self-hosting", "/#self-hosting"],
              ["Download", "/#download"],
              ["FAQ", "/#faq"],
            ].map(([label, href]) => (
              <ListItemButton
                key={href}
                component="a"
                href={href}
                onClick={() => setMenuOpen(false)}
              >
                <ListItemText primary={label} />
              </ListItemButton>
            ))}
            {info.data?.docs !== false && (
              <ListItemButton
                component={info.data?.docs_url ? "a" : RouterLink}
                {...(info.data?.docs_url ? { href: info.data.docs_url } : { to: "/docs" })}
                onClick={() => setMenuOpen(false)}
              >
                <ListItemText primary="Docs" />
              </ListItemButton>
            )}
            <ListItemButton component="a" href={REPO} target="_blank" rel="noreferrer">
              <ListItemText primary="GitHub" />
            </ListItemButton>
          </List>
          <Divider />
          <List>
            {session ? (
              <ListItemButton
                component={RouterLink}
                to="/account"
                onClick={() => setMenuOpen(false)}
              >
                <ListItemText primary="Open cabinet" />
              </ListItemButton>
            ) : (
              <>
                <ListItemButton
                  component={RouterLink}
                  to="/login"
                  onClick={() => setMenuOpen(false)}
                >
                  <ListItemText primary="Log in" />
                </ListItemButton>
                {registrationOpen && (
                  <ListItemButton
                    component={RouterLink}
                    to="/signup"
                    onClick={() => setMenuOpen(false)}
                  >
                    <ListItemText primary="Sign up" />
                  </ListItemButton>
                )}
              </>
            )}
          </List>
        </Box>
      </Drawer>
    </>
  );
}

/** Site footer shared by the landing and the public pages. */
export function LandingFooter() {
  const info = useServerInfo();
  return (
    <Box component="footer" sx={{ borderTop: 1, borderColor: "border.light", py: 6 }}>
      <Container maxWidth="lg">
        <Box
          sx={{
            display: "grid",
            gridTemplateColumns: { xs: "1fr 1fr", md: "2fr 1fr 1fr 1fr" },
            gap: 4,
          }}
        >
          <Box sx={{ gridColumn: { xs: "1 / -1", md: "auto" } }}>
            <Logo size={24} />
            <Typography variant="body2" color="text.secondary" sx={{ mt: 1.5, maxWidth: 300 }}>
              Software should report to you, not on you. Free, open source, self-hosted.
            </Typography>
          </Box>
          {(
            [
              {
                title: "Product",
                links: [
                  ["Download", RELEASES],
                  ["Releases", `${REPO}/releases`],
                  ["Security", "/#security"],
                ],
              },
              {
                title: "Self-hosting",
                links: [
                  ["Quick start", README],
                  ["Docker Compose", `${REPO}/blob/main/deploy/docker-compose.yml`],
                  ["Self-hosting guide", SELF_HOSTING],
                ],
              },
              {
                title: "Project",
                links: [
                  ["GitHub", REPO],
                  ["Issues", `${REPO}/issues`],
                  ["Sponsor", "/sponsor"],
                  ["License (AGPL-3.0)", `${REPO}/blob/main/LICENSE`],
                ],
              },
            ] as { title: string; links: [string, string][] }[]
          ).map((col) => (
            <Box key={col.title}>
              <Typography variant="subtitle2" sx={{ mb: 1.5 }}>
                {col.title}
              </Typography>
              <Stack spacing={1}>
                {col.links.map(([label, href]) => (
                  <Link
                    key={label}
                    href={href}
                    target={href.startsWith("/") ? undefined : "_blank"}
                    rel="noreferrer"
                    variant="body2"
                    color="text.secondary"
                    underline="hover"
                  >
                    {label}
                  </Link>
                ))}
              </Stack>
            </Box>
          ))}
        </Box>
        <Typography
          variant="caption"
          color="text.disabled"
          sx={{ display: "block", mt: 5, pt: 3, borderTop: 1, borderColor: "border.light" }}
        >
          {info.data ? `${info.data.name} · server v${info.data.version}` : "Termoso"} · AGPL-3.0 ·
          No cookies, no trackers.
        </Typography>
        <Typography variant="caption" color="text.disabled" sx={{ display: "block", mt: 1 }}>
          Termius is a trademark of Termius Corporation. Termoso is an independent project, not
          affiliated with or endorsed by Termius.
        </Typography>
      </Container>
    </Box>
  );
}

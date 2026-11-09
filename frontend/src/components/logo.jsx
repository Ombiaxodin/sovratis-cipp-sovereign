// [SOVRATIS OVERRIDE START]
// Upstream renders an inlined CIPP logo (a ~30 KB base64 payload) and throws if that payload is altered. Sovratis
// ships its own brand assets, so the payload and the tamper guard are removed and the file is replaced as a whole.
// The asset is chosen from the active MUI theme: the "header" lockup (dark text) for light backgrounds, the
// "banner" lockup (light text) for dark backgrounds. Files live in public/.
import PropTypes from "prop-types";
import { useTheme } from "@mui/material/styles";

export const LOGO_FOR_LIGHT_BACKGROUND = "/header-logo_245x36.png";
export const LOGO_FOR_DARK_BACKGROUND = "/banner-logo_245x36.png";

export const Logo = ({ mode }) => {
  const theme = useTheme();
  const effectiveMode = mode ?? theme.palette.mode;
  return (
    <img
      src={effectiveMode === "dark" ? LOGO_FOR_DARK_BACKGROUND : LOGO_FOR_LIGHT_BACKGROUND}
      alt="Sovratis"
      width={245}
      height={36}
      // fills the height of its container; the wordmark is wider than tall, so width follows
      style={{ display: "block", height: "100%", width: "auto", maxWidth: "none" }}
    />
  );
};

Logo.propTypes = {
  // force a variant regardless of theme, for surfaces whose background does not follow it
  mode: PropTypes.oneOf(["light", "dark"]),
};
// [SOVRATIS OVERRIDE END]

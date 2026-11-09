import { common } from '@mui/material/colors';
import { alpha } from '@mui/material/styles';
import { error, info, neutral, success, warning } from '../colors';
// [SOVRATIS OVERRIDE START]
import { orange } from '../colors';
// [SOVRATIS OVERRIDE END]
import { getPrimary } from '../utils';

export const createPalette = (config) => {
  const { colorPreset, contrast } = config;

  return {
    action: {
      active: neutral[400],
      // A mid-grey at 0.38 over the disabled background is ~2:1 here, which erases icon-only
      // disabled controls; white at 0.5 keeps them readable while still reading as disabled.
      disabled: alpha(common.white, 0.5),
      disabledBackground: alpha(neutral[400], 0.12),
      focus: alpha(neutral[400], 0.16),
      hover: alpha(neutral[400], 0.04),
      selected: alpha(neutral[400], 0.12)
    },
    background: {
      default: contrast === 'high' ? '#0A0F18' : '#0C121D',
      paper: '#101826'
    },
    divider: neutral[800],
    error,
    info,
    mode: 'dark',
    neutral,
    // [SOVRATIS OVERRIDE START]
    // Petrol (#0B3D3A) on the dark background (#0A0F18) is about 1.6:1, so primary and accent are both Amber in dark mode
    // upstream: primary: getPrimary(colorPreset),
    primary: orange,
    secondary: orange,
    // [SOVRATIS OVERRIDE END]
    success,
    text: {
      primary: common.white,
      secondary: '#97A1BA',
      disabled: alpha(common.white, 0.38)
    },
    warning
  };
};

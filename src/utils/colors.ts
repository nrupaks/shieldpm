/**
 * ShieldPM — Terminal color helpers (zero dependencies)
 * Simple ANSI escape code wrapper, no chalk needed.
 */

const isColorSupported = (): boolean => {
  if (process.env.NO_COLOR !== undefined) return false;
  if (process.env.FORCE_COLOR !== undefined) return true;
  if (!process.stdout.isTTY) return false;
  return true;
};

const enabled = isColorSupported();

const wrap = (open: string, close: string) => {
  return (text: string): string => {
    if (!enabled) return text;
    return `\x1b[${open}m${text}\x1b[${close}m`;
  };
};

// Foreground colors
export const red = wrap('31', '39');
export const green = wrap('32', '39');
export const yellow = wrap('33', '39');
export const blue = wrap('34', '39');
export const magenta = wrap('35', '39');
export const cyan = wrap('36', '39');
export const white = wrap('37', '39');
export const gray = wrap('90', '39');

// Styles
export const bold = wrap('1', '22');
export const dim = wrap('2', '22');
export const italic = wrap('3', '23');
export const underline = wrap('4', '24');

// Reset
export const reset = wrap('0', '0');

// Bright variants
export const redBright = wrap('91', '39');
export const greenBright = wrap('92', '39');
export const yellowBright = wrap('93', '39');
export const blueBright = wrap('94', '39');
export const cyanBright = wrap('96', '39');

// Background colors
export const bgRed = wrap('41', '49');
export const bgGreen = wrap('42', '49');
export const bgYellow = wrap('43', '49');

// Composable: bold + color
export const boldRed = (t: string) => bold(red(t));
export const boldGreen = (t: string) => bold(green(t));
export const boldYellow = (t: string) => bold(yellow(t));
export const boldCyan = (t: string) => bold(cyan(t));
export const boldBlue = (t: string) => bold(blue(t));

/* Inline SVG icons — no external dependency. 1.6px stroke, currentColor. */
import type { SVGProps } from "react";

type P = SVGProps<SVGSVGElement> & { size?: number };

function Svg({ size = 18, children, ...rest }: P & { children: React.ReactNode }) {
  return (
    <svg
      className="icon"
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.7}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      {...rest}
    >
      {children}
    </svg>
  );
}

export const IconShield = (p: P) => (
  <Svg {...p}><path d="M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3z" /><path d="M9 12l2 2 4-4" /></Svg>
);
// Spectris brandmark — centered Wi-Fi (visible centre dot) + a golden lightning
// accent offset to the right, matching the app icon.
export const IconSpectris = ({ size = 20 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" className="icon" aria-hidden="true">
    <g stroke="#eef5ff" strokeWidth="1.9" strokeLinecap="round">
      <path d="M6 10.9a6 6 0 0 1 10 0" />
      <path d="M8.3 12.9a3.2 3.2 0 0 1 5.4 0" />
    </g>
    <circle cx="11" cy="15" r="1.2" fill="#eef5ff" />
    <path d="M16.8 7.6 L14.2 12 L15.7 12 L14 16 L17.4 10.8 L15.7 10.8 Z" fill="#f6b942" stroke="#c9871a" strokeWidth="0.4" strokeLinejoin="round" />
  </svg>
);
export const IconSetup = (p: P) => (
  <Svg {...p}><circle cx="12" cy="12" r="3" /><path d="M4 12h2M18 12h2M12 4v2M12 18v2M6 6l1.5 1.5M16.5 16.5L18 18M18 6l-1.5 1.5M7.5 16.5L6 18" /></Svg>
);
export const IconTarget = (p: P) => (
  <Svg {...p}><circle cx="12" cy="12" r="8" /><circle cx="12" cy="12" r="4" /><circle cx="12" cy="12" r="1" /></Svg>
);
export const IconScan = (p: P) => (
  <Svg {...p}><path d="M5 12.5a10 10 0 0 1 14 0" /><path d="M8 15.5a6 6 0 0 1 8 0" /><circle cx="12" cy="18.5" r="1" /><path d="M2 8.5a15 15 0 0 1 20 0" /></Svg>
);
export const IconBolt = (p: P) => (
  <Svg {...p}><path d="M13 2L4 14h7l-1 8 9-12h-7l1-8z" /></Svg>
);
export const IconWps = (p: P) => (
  <Svg {...p}><rect x="3" y="4" width="18" height="16" rx="2" /><path d="M7 9h4M7 13h2" /><circle cx="16.5" cy="11" r="2.2" /><path d="M16.5 13.2V16" /></Svg>
);
export const IconLog = (p: P) => (
  <Svg {...p}><path d="M4 5h16M4 12h16M4 19h10" /></Svg>
);
export const IconCheck = (p: P) => (<Svg {...p}><path d="M4 12l5 5L20 6" /></Svg>);
export const IconX = (p: P) => (<Svg {...p}><path d="M6 6l12 12M18 6L6 18" /></Svg>);
export const IconAlert = (p: P) => (
  <Svg {...p}><path d="M12 3l9 16H3l9-16z" /><path d="M12 10v4M12 17h.01" /></Svg>
);
export const IconInfo = (p: P) => (<Svg {...p}><circle cx="12" cy="12" r="9" /><path d="M12 11v5M12 8h.01" /></Svg>);
export const IconPlay = (p: P) => (<Svg {...p}><path d="M7 5l12 7-12 7V5z" /></Svg>);
export const IconStop = (p: P) => (<Svg {...p}><rect x="6" y="6" width="12" height="12" rx="2" /></Svg>);
export const IconRefresh = (p: P) => (
  <Svg {...p}><path d="M20 11a8 8 0 0 0-14-5L4 8" /><path d="M4 4v4h4" /><path d="M4 13a8 8 0 0 0 14 5l2-2" /><path d="M20 20v-4h-4" /></Svg>
);
export const IconChip = (p: P) => (
  <Svg {...p}><rect x="7" y="7" width="10" height="10" rx="1.5" /><path d="M10 3v2M14 3v2M10 19v2M14 19v2M3 10h2M3 14h2M19 10h2M19 14h2" /></Svg>
);
export const IconLock = (p: P) => (
  <Svg {...p}><rect x="5" y="11" width="14" height="9" rx="2" /><path d="M8 11V8a4 4 0 0 1 8 0v3" /></Svg>
);
export const IconDownload = (p: P) => (
  <Svg {...p}><path d="M12 3v12M7 11l5 5 5-5" /><path d="M5 21h14" /></Svg>
);
export const IconClone = (p: P) => (
  <Svg {...p}><rect x="4" y="4" width="12" height="12" rx="2" /><path d="M8 20h10a2 2 0 0 0 2-2V8" /></Svg>
);
export const IconKey = (p: P) => (
  <Svg {...p}><circle cx="8" cy="15" r="4" /><path d="M10.8 12.2L20 3M17 6l2 2M14 9l2 2" /></Svg>
);
export const IconTerminal = (p: P) => (
  <Svg {...p}><rect x="3" y="4" width="18" height="16" rx="2" /><path d="M7 9l3 3-3 3M13 15h4" /></Svg>
);
export const IconTrash = (p: P) => (
  <Svg {...p}><path d="M4 7h16M9 7V5a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2M6 7l1 13a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1l1-13M10 11v6M14 11v6" /></Svg>
);
export const IconExternal = (p: P) => (
  <Svg {...p}><path d="M14 5h5v5M19 5l-8 8M18 14v4a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h4" /></Svg>
);
export const IconContrast = (p: P) => (
  <Svg {...p}><circle cx="12" cy="12" r="9" /><path d="M12 3v18a9 9 0 0 0 0-18z" fill="currentColor" stroke="none" /></Svg>
);
// Brand marks — filled (currentColor), own <svg> since they aren't stroke icons.
export const IconGithub = ({ size = 18, ...rest }: P) => (
  <svg className="icon" width={size} height={size} viewBox="0 0 24 24" fill="currentColor" aria-hidden="true" {...rest}>
    <path d="M12 2C6.48 2 2 6.58 2 12.26c0 4.5 2.87 8.32 6.84 9.67.5.09.68-.22.68-.48 0-.24-.01-.87-.01-1.7-2.78.62-3.37-1.21-3.37-1.21-.46-1.18-1.11-1.49-1.11-1.49-.91-.63.07-.62.07-.62 1 .07 1.53 1.05 1.53 1.05.89 1.56 2.34 1.11 2.91.85.09-.66.35-1.11.63-1.37-2.22-.26-4.56-1.14-4.56-5.07 0-1.12.39-2.03 1.03-2.75-.1-.26-.45-1.3.1-2.71 0 0 .84-.27 2.75 1.05A9.3 9.3 0 0 1 12 6.84c.85 0 1.71.12 2.51.34 1.91-1.32 2.75-1.05 2.75-1.05.55 1.41.2 2.45.1 2.71.64.72 1.03 1.63 1.03 2.75 0 3.94-2.34 4.81-4.57 5.06.36.32.68.94.68 1.9 0 1.37-.01 2.47-.01 2.81 0 .27.18.58.69.48A10.02 10.02 0 0 0 22 12.26C22 6.58 17.52 2 12 2z" />
  </svg>
);
export const IconLinkedin = ({ size = 18, ...rest }: P) => (
  <svg className="icon" width={size} height={size} viewBox="0 0 24 24" fill="currentColor" aria-hidden="true" {...rest}>
    <path d="M4.98 3.5a2.5 2.5 0 1 1 0 5 2.5 2.5 0 0 1 0-5zM3 9h4v12H3zM9 9h3.8v1.71h.05c.53-.95 1.83-1.95 3.76-1.95 4.02 0 4.76 2.5 4.76 5.75V21h-4v-5.37c0-1.28-.02-2.93-1.78-2.93-1.79 0-2.06 1.4-2.06 2.84V21H9z" />
  </svg>
);

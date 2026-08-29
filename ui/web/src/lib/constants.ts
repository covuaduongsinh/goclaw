// Barrel re-exports for backward compatibility.
// Import directly from sub-modules for new code.
export { ROUTES } from "./routes";
export {
  TIMEZONE_OPTIONS,
  getAllIanaTimezones,
  isValidIanaTimezone,
} from "./timezone-utils";

export const LOCAL_STORAGE_KEYS = {
  TOKEN: "goclaw:token",
  USER_ID: "goclaw:userId",
  SENDER_ID: "goclaw:senderID",
  TENANT_ID: "goclaw:tenant_id",
  TENANT_HINT: "goclaw:tenant_hint",
  SETUP_SKIPPED: "goclaw:setup_skipped",
  THEME: "goclaw:theme",
  SIDEBAR_COLLAPSED: "goclaw:sidebarCollapsed",
  LANGUAGE: "goclaw:language",
  TIMEZONE: "goclaw:timezone",
} as const;

// Tokens issued by POST /v1/auth/login. The prefix distinguishes them from a
// gateway token or an API key ("goclaw_"), which the client has to tell apart:
// an account may legitimately hold the viewer role, while a gateway token that
// resolves to viewer means the token is wrong.
export const SESSION_TOKEN_PREFIX = "goclaws_";

export const SUPPORTED_LANGUAGES = ["en", "vi", "zh", "ko", "ru"] as const;
export type Language = (typeof SUPPORTED_LANGUAGES)[number];

export const LANGUAGE_LABELS: Record<Language, string> = {
  en: "English",
  vi: "Tiếng Việt",
  zh: "中文",
  ko: "한국어",
  ru: "Русский",
};

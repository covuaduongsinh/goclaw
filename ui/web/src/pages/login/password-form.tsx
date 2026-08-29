import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useTranslation } from "react-i18next";
import { AlertCircle } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { passwordFormSchema, type PasswordFormData } from "@/schemas/login.schema";

interface PasswordFormProps {
  onSuccess: (userId: string, token: string) => void;
}

/**
 * Email + password sign-in.
 *
 * The request goes out through plain fetch rather than the shared httpClient
 * on purpose: httpClient attaches whatever token is already in the store and
 * calls onAuthFailure on a 401, which would sign the visitor out of a session
 * they are in the middle of starting.
 */
export function PasswordForm({ onSuccess }: PasswordFormProps) {
  const { t } = useTranslation("login");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<PasswordFormData>({
    resolver: zodResolver(passwordFormSchema),
    defaultValues: { email: "", password: "" },
  });

  const onValid = async (data: PasswordFormData) => {
    setSubmitting(true);
    setError(null);

    try {
      const res = await fetch("/v1/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: data.email.trim(),
          password: data.password,
        }),
      });

      if (res.status === 401) {
        setError(t("password.errorInvalidCredentials"));
        return;
      }
      if (res.status === 429) {
        setError(t("password.errorTooManyAttempts"));
        return;
      }
      if (res.status === 503) {
        setError(t("password.errorAccountsUnavailable"));
        return;
      }
      if (!res.ok) {
        setError(t("password.errorServer", { status: res.status }));
        return;
      }

      const body = (await res.json()) as {
        token?: string;
        user?: { user_id?: string };
        tenants?: { tenant_id: string; slug: string }[];
      };
      if (!body.token || !body.user?.user_id) {
        setError(t("password.errorServer", { status: res.status }));
        return;
      }

      // Preselect the tenant when the account belongs to exactly one, so the
      // first request already carries the right scope. With several, the
      // tenant picker takes over after the redirect.
      const onlyTenant = body.tenants?.length === 1 ? body.tenants[0] : undefined;
      if (onlyTenant) {
        localStorage.setItem("goclaw:tenant_id", onlyTenant.tenant_id);
        localStorage.setItem("goclaw:tenant_hint", onlyTenant.slug ?? "");
      }

      onSuccess(body.user.user_id, body.token);
    } catch {
      setError(t("password.errorCannotConnect"));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <form onSubmit={handleSubmit(onValid)} className="space-y-4" method="post" action="/v1/auth/login">
      <div className="space-y-2">
        <Label htmlFor="email" className="text-sm font-medium">
          {t("password.email")}
        </Label>
        <Input
          id="email"
          type="email"
          autoComplete="username"
          {...register("email")}
          placeholder={t("password.emailPlaceholder")}
          className="text-base md:text-sm"
          autoFocus
          disabled={submitting}
          aria-describedby={error ? "login-error" : undefined}
        />
        {errors.email && (
          <p className="text-xs text-destructive">{errors.email.message}</p>
        )}
      </div>

      <div className="space-y-2">
        <Label htmlFor="password" className="text-sm font-medium">
          {t("password.password")}
        </Label>
        <Input
          id="password"
          type="password"
          autoComplete="current-password"
          {...register("password")}
          placeholder={t("password.passwordPlaceholder")}
          className="text-base md:text-sm"
          disabled={submitting}
          aria-describedby={error ? "login-error" : undefined}
        />
        {errors.password && (
          <p className="text-xs text-destructive">{errors.password.message}</p>
        )}
      </div>

      {error && (
        <div
          id="login-error"
          role="alert"
          className="flex items-start gap-2 rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive"
        >
          <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      <button
        type="submit"
        disabled={submitting}
        className="inline-flex h-9 w-full items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground shadow transition-colors hover:bg-primary/90 disabled:pointer-events-none disabled:opacity-50"
      >
        {submitting ? t("password.signingIn") : t("password.signIn")}
      </button>
    </form>
  );
}

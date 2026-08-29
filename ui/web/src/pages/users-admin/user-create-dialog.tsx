import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import type { UserCreateInput } from "@/types/user";

interface UserCreateDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onCreate: (input: UserCreateInput) => Promise<unknown>;
  /** Tenants the signed-in administrator can grant membership in. */
  tenants: { id: string; name: string }[];
}

const TENANT_ROLES = ["owner", "admin", "operator", "member", "viewer"] as const;

/**
 * Creates an account.
 *
 * Tenant and role are part of this form rather than a follow-up step because
 * an account with no membership signs in as a viewer with no tenant, which the
 * dashboard treats as a failed sign-in.
 */
export function UserCreateDialog({ open, onOpenChange, onCreate, tenants }: UserCreateDialogProps) {
  const { t } = useTranslation("users");
  const { t: tc } = useTranslation("common");

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [userId, setUserId] = useState("");
  const [tenantId, setTenantId] = useState(tenants[0]?.id ?? "");
  const [role, setRole] = useState<string>("member");
  const [mustChange, setMustChange] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const canSubmit = email.trim().length > 0 && password.length >= 12;

  const reset = () => {
    setEmail("");
    setPassword("");
    setDisplayName("");
    setUserId("");
    setRole("member");
    setMustChange(true);
    setError(null);
  };

  const handleSubmit = async () => {
    setSubmitting(true);
    setError(null);
    try {
      await onCreate({
        email: email.trim(),
        password,
        user_id: userId.trim() || undefined,
        display_name: displayName.trim() || undefined,
        tenant_id: tenantId || undefined,
        tenant_role: tenantId ? role : undefined,
        must_change_password: mustChange,
      });
      reset();
      onOpenChange(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{t("create.title")}</DialogTitle>
          <DialogDescription>{t("create.description")}</DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="new-user-email">{t("fields.email")}</Label>
            <Input
              id="new-user-email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@example.com"
              className="text-base md:text-sm"
              autoComplete="off"
              disabled={submitting}
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="new-user-password">{t("fields.password")}</Label>
            <Input
              id="new-user-password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="text-base md:text-sm"
              autoComplete="new-password"
              disabled={submitting}
            />
            <p className="text-xs text-muted-foreground">{t("create.passwordHint")}</p>
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="new-user-name">{t("fields.displayName")}</Label>
              <Input
                id="new-user-name"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                className="text-base md:text-sm"
                disabled={submitting}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="new-user-id">{t("fields.userId")}</Label>
              <Input
                id="new-user-id"
                value={userId}
                onChange={(e) => setUserId(e.target.value)}
                placeholder={t("create.userIdPlaceholder")}
                className="text-base md:text-sm"
                disabled={submitting}
              />
            </div>
          </div>
          <p className="text-xs text-muted-foreground">{t("create.userIdHint")}</p>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="new-user-tenant">{t("fields.tenant")}</Label>
              <select
                id="new-user-tenant"
                value={tenantId}
                onChange={(e) => setTenantId(e.target.value)}
                disabled={submitting}
                className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-base shadow-sm md:text-sm"
              >
                <option value="">{t("create.noTenant")}</option>
                {tenants.map((tenant) => (
                  <option key={tenant.id} value={tenant.id}>
                    {tenant.name}
                  </option>
                ))}
              </select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="new-user-role">{t("fields.role")}</Label>
              <select
                id="new-user-role"
                value={role}
                onChange={(e) => setRole(e.target.value)}
                disabled={submitting || !tenantId}
                className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-base shadow-sm md:text-sm"
              >
                {TENANT_ROLES.map((r) => (
                  <option key={r} value={r}>
                    {r}
                  </option>
                ))}
              </select>
            </div>
          </div>
          {!tenantId && (
            <p className="text-xs text-amber-600 dark:text-amber-500">{t("create.noTenantWarning")}</p>
          )}

          <div className="flex items-center justify-between rounded-md border px-3 py-2">
            <div>
              <Label htmlFor="new-user-must-change">{t("fields.mustChangePassword")}</Label>
              <p className="text-xs text-muted-foreground">{t("create.mustChangeHint")}</p>
            </div>
            <Switch
              id="new-user-must-change"
              checked={mustChange}
              onCheckedChange={setMustChange}
              disabled={submitting}
            />
          </div>

          {error && (
            <p role="alert" className="text-sm text-destructive">
              {error}
            </p>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={submitting}>
            {tc("cancel")}
          </Button>
          <Button onClick={handleSubmit} disabled={!canSubmit || submitting}>
            {submitting ? t("create.creating") : t("create.submit")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

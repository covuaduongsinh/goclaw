import { useState, lazy, Suspense } from "react";
import { useTranslation } from "react-i18next";
import { KeyRound, Plus, RefreshCw, Trash2, UserCog, Users } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { PageHeader } from "@/components/shared/page-header";
import { EmptyState } from "@/components/shared/empty-state";
import { SearchInput } from "@/components/shared/search-input";
import { TableSkeleton } from "@/components/shared/loading-skeleton";
import { ConfirmDeleteDialog } from "@/components/shared/confirm-delete-dialog";
import { useMinLoading } from "@/hooks/use-min-loading";
import { useDeferredLoading } from "@/hooks/use-deferred-loading";
import { useTenants } from "@/hooks/use-tenants";
import { formatRelativeTime } from "@/lib/format";
import { useUsers } from "./hooks/use-users";
import type { UserAccount } from "@/types/user";

const UserCreateDialog = lazy(() =>
  import("./user-create-dialog").then((m) => ({ default: m.UserCreateDialog }))
);

export function UsersAdminPage() {
  const { t } = useTranslation("users");
  const { t: tc } = useTranslation("common");
  const { users, loading, refresh, createUser, updateUser, deleteUser, setPassword, revokeSessions } =
    useUsers();
  const { tenants } = useTenants();

  const spinning = useMinLoading(loading);
  const showSkeleton = useDeferredLoading(loading && users.length === 0);

  const [search, setSearch] = useState("");
  const [createOpen, setCreateOpen] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<UserAccount | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [passwordTarget, setPasswordTarget] = useState<UserAccount | null>(null);
  const [newPassword, setNewPassword] = useState("");
  const [savingPassword, setSavingPassword] = useState(false);

  const term = search.toLowerCase();
  const filtered = users.filter(
    (u) =>
      u.email.toLowerCase().includes(term) ||
      u.user_id.toLowerCase().includes(term) ||
      u.display_name.toLowerCase().includes(term),
  );

  const handleDelete = async () => {
    if (!deleteTarget) return;
    setDeleting(true);
    try {
      await deleteUser(deleteTarget.id);
      setDeleteTarget(null);
    } finally {
      setDeleting(false);
    }
  };

  const handleSetPassword = async () => {
    if (!passwordTarget) return;
    setSavingPassword(true);
    try {
      // Forcing a change is the default: whoever performed the reset now knows
      // the password, so it must not remain the account's long-term secret.
      await setPassword(passwordTarget.id, newPassword, true);
      setPasswordTarget(null);
      setNewPassword("");
    } finally {
      setSavingPassword(false);
    }
  };

  const toggleStatus = async (user: UserAccount) => {
    await updateUser(user.id, {
      status: user.status === "active" ? "disabled" : "active",
    });
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title={t("title")}
        description={t("description")}
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => refresh()} disabled={spinning}>
              <RefreshCw className={`h-4 w-4 ${spinning ? "animate-spin" : ""}`} />
              <span className="ml-2 hidden sm:inline">{tc("refresh")}</span>
            </Button>
            <Button size="sm" onClick={() => setCreateOpen(true)}>
              <Plus className="h-4 w-4" />
              <span className="ml-2">{t("create.submit")}</span>
            </Button>
          </div>
        }
      />

      <SearchInput value={search} onChange={setSearch} placeholder={t("searchPlaceholder")} />

      {showSkeleton ? (
        <TableSkeleton rows={5} />
      ) : filtered.length === 0 ? (
        <EmptyState
          icon={Users}
          title={t("empty.title")}
          description={search ? t("empty.noMatch") : t("empty.description")}
        />
      ) : (
        <div className="overflow-x-auto rounded-md border">
          <table className="w-full min-w-[600px] text-sm">
            <thead className="border-b bg-muted/50 text-left">
              <tr>
                <th className="px-4 py-2 font-medium">{t("fields.email")}</th>
                <th className="px-4 py-2 font-medium">{t("fields.userId")}</th>
                <th className="px-4 py-2 font-medium">{t("fields.status")}</th>
                <th className="px-4 py-2 font-medium">{t("fields.lastLogin")}</th>
                <th className="px-4 py-2 font-medium text-right">{tc("actions")}</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((user) => (
                <tr key={user.id} className="border-b last:border-0">
                  <td className="px-4 py-2">
                    <div className="font-medium">{user.email}</div>
                    {user.display_name && (
                      <div className="text-xs text-muted-foreground">{user.display_name}</div>
                    )}
                  </td>
                  <td className="px-4 py-2 font-mono text-xs">{user.user_id}</td>
                  <td className="px-4 py-2">
                    <Badge variant={user.status === "active" ? "default" : "secondary"}>
                      {t(`status.${user.status}`)}
                    </Badge>
                    {user.must_change_password && (
                      <Badge variant="secondary" className="ml-1">
                        {t("status.mustChange")}
                      </Badge>
                    )}
                  </td>
                  <td className="px-4 py-2 text-muted-foreground">
                    {user.last_login_at ? formatRelativeTime(user.last_login_at) : t("neverSignedIn")}
                  </td>
                  <td className="px-4 py-2">
                    <div className="flex items-center justify-end gap-1">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => setPasswordTarget(user)}
                        title={t("actions.setPassword")}
                      >
                        <KeyRound className="h-4 w-4" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => toggleStatus(user)}
                        title={user.status === "active" ? t("actions.disable") : t("actions.enable")}
                      >
                        <UserCog className="h-4 w-4" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => revokeSessions(user.id)}
                        title={t("actions.revokeSessions")}
                      >
                        <RefreshCw className="h-4 w-4" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => setDeleteTarget(user)}
                        title={tc("delete")}
                      >
                        <Trash2 className="h-4 w-4 text-destructive" />
                      </Button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {createOpen && (
        <Suspense fallback={null}>
          <UserCreateDialog
            open={createOpen}
            onOpenChange={setCreateOpen}
            onCreate={createUser}
            tenants={tenants.map((tenant) => ({ id: tenant.id, name: tenant.name }))}
          />
        </Suspense>
      )}

      <ConfirmDeleteDialog
        open={deleteTarget !== null}
        onOpenChange={(open) => !open && setDeleteTarget(null)}
        title={t("delete.title")}
        description={t("delete.description", { email: deleteTarget?.email ?? "" })}
        confirmValue={deleteTarget?.email ?? ""}
        onConfirm={handleDelete}
        loading={deleting}
      />

      <Dialog
        open={passwordTarget !== null}
        onOpenChange={(open) => {
          if (!open) {
            setPasswordTarget(null);
            setNewPassword("");
          }
        }}
      >
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>{t("setPassword.title")}</DialogTitle>
            <DialogDescription>
              {t("setPassword.description", { email: passwordTarget?.email ?? "" })}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-2">
            <Label htmlFor="reset-password">{t("fields.password")}</Label>
            <Input
              id="reset-password"
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              className="text-base md:text-sm"
              autoComplete="new-password"
              disabled={savingPassword}
            />
            <p className="text-xs text-muted-foreground">{t("setPassword.hint")}</p>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                setPasswordTarget(null);
                setNewPassword("");
              }}
              disabled={savingPassword}
            >
              {tc("cancel")}
            </Button>
            <Button onClick={handleSetPassword} disabled={newPassword.length < 12 || savingPassword}>
              {savingPassword ? tc("saving") : tc("save")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

import { Outlet, useLocation } from "react-router";
import { MemberBrandedPanel } from "../components/member/MemberBrandedPanel";
import { useAuth } from "../contexts/AuthContext";
import { CS01StorageOverview } from "../screens/storage/CS01StorageOverview";
import { isMemberRole } from "../utils/authorization";

/**
 * Files has a purpose-built member workspace on tablet/desktop:
 *
 *   narrow left pane  -> Vault browser and upload controls
 *   large right pane  -> selected file details or secure transfer workflow
 *
 * Admin sessions keep using the regular storage routes unchanged. Mobile
 * remains a single-pane navigation flow so each screen has the full width.
 */
export function MemberStorageLayout() {
  const { session } = useAuth();
  const location = useLocation();
  const memberSession = isMemberRole(session?.user.role);
  const pendingMemberSession = memberSession && (session?.circleIds.length || 0) === 0;
  const atVaultRoot = location.pathname.replace(/\/+$/, "") === "/storage";

  if (!memberSession || pendingMemberSession) return <Outlet />;

  return (
    <>
      <div className="h-full lg:hidden">
        <Outlet />
      </div>

      <div className="hidden h-full min-h-0 lg:flex">
        <aside className="h-full min-h-0 w-[460px] shrink-0 xl:w-[560px] overflow-hidden border-r border-border">
          <CS01StorageOverview />
        </aside>
        <section className="h-full min-h-0 min-w-0 flex-1 overflow-hidden">
          {atVaultRoot ? <MemberBrandedPanel context="files" /> : <Outlet />}
        </section>
      </div>
    </>
  );
}

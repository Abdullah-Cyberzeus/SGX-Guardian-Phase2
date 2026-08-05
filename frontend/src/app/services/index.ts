// Export all services
export { default as api } from './api';
export { default as nodeService } from './nodeService';
export { default as peerService } from './peerService';
export { default as attestationService } from './attestationService';
export { default as logService } from './logService';
export { default as dkpService } from './dkpService';
export { default as policyService } from './policyService';
export { default as pcrService } from './pcrService';
export { default as alertService } from './alertService';
export { default as deviceService } from './deviceService';
export { default as circleService } from './circleService';
export { default as guardianService } from './guardianService';
export { default as didService } from './didService';
export { default as transportService } from './transportService';
export { default as relayService } from './relayService';
export { default as vcService } from './vcService';
export { default as vidService } from './vidService';
export { default as discoveryService } from './discoveryService';
export { default as crlService } from './crlService';
export { default as backupService } from './backupService';
export { default as managedDeviceService } from './managedDeviceService';
export { default as smartHomeService, openSmartHomeSocket } from './smartHomeService';

// Export types
export type { NodeStatus, BootStatus } from './nodeService';
export type { Peer } from './peerService';
export type { AttestationResult } from './attestationService';
export type { LogEntry, LogsResponse } from './logService';
export type { DKPKey, DKPStatus } from './dkpService';
export type { Policy } from './policyService';
export type { PCRRegister, PCRStatus, PCRBaseline } from './pcrService';
export type { Alert, AlertsResponse } from './alertService';
export type { Device, DevicesResponse } from './deviceService';
export type { Circle } from './circleService';
export type { GuardianInfo, GuardianHealth, GuardianMetrics } from './guardianService';
export type {
  DIDStatus,
  DIDResolveResult,
  DIDDeactivateResponse,
  DIDDocumentSummary,
  DIDDocumentRaw,
  DIDDocumentVerifyResponse,
  DIDDocumentPublishResponse,
  DIDDocumentPeerSummary,
  DIDDocumentPeersResponse,
} from './didService';
export type {
  TransportInterface,
  TransportListResponse,
  TransportStatusResponse,
  TransportLockResponse,
} from './transportService';
export type {
  RelayNode,
  RegistryNode,
  RelayListResponse,
  LighthouseListResponse,
  MemberListResponse,
  RelayLighthouseListResponse,
  RelayLimitsResponse,
  RelayToggleResponse,
} from './relayService';
export type {
  VerifiableCredential,
  VcMetaItem,
  IssueVcRequest,
  IssueVcResponse,
  RenewVcRequest,
  RenewVcResponse,
  RevokeVcRequest,
  RevokeVcResponse,
  VerifyVcResponse,
  VcShowFilters,
  VcShowResponse,
  VcStatusResponse,
  PullStatusListRequest,
  PullStatusListResponse,
  VcFilesIssuedResponse,
  VcFilesOwnResponse,
  VcFilesPeersResponse,
  VcStatusListResponse,
  VcStatusListIndexResponse,
  VcSummaryResponse,
  VcAuditFilters,
  VcAuditAction,
  VcAuditSeverity,
  VcAuditItem,
  VcAuditResponse,
} from './vcService';
export type {
  VidChangeReason,
  VidShowResponse,
  VidPeer,
  VidPeersResponse,
} from './vidService';
export type {
  OpenPort,
  ConnectedDevice,
  DiscoveryIntensity,
  DiscoveryScanResponse,
  ApproveDeviceRequest,
  ApproveDeviceResponse,
  WhitelistDevice,
  WhitelistDoc,
  ScheduleEntry,
  DiscoverySchedule,
} from './discoveryService';

export type {
  CrlSeverity,
  CrlReason,
  CrlProof,
  CrlEntry,
  CrlListResponse,
  CrlRootResponse,
  CrlVerifyResponse,
  CrlCheckResponse,
  CrlRevokePayload,
  CrlRevokeResponse,
  CrlUnrevokeResponse,
} from './crlService';

export type {
  BackupComponent,
  BackupRecord,
  BackupHistoryResponse,
  CreateBackupRequest,
  DeleteBackupResponse,
  BackupValidateRequest,
  BackupValidateComponent,
  BackupValidateResponse,
  RestoreValidateRequest,
  RestorePlanStep,
  RestoreValidateResponse,
  RestoreApplyRequest,
  RestoreApplyResponse,
  RestoreJournal,
  RestoreStatusResponse,
  RestoreUndoResponse,
} from './backupService';
export { ALL_BACKUP_COMPONENTS } from './backupService';

export type {
  RiskLevel,
  ScriptResult,
  OpenPort as ManagedDeviceOpenPort,
  DeviceScores,
  ManagedDevice,
  ScoreDistribution,
  ManagedDevicesSummary,
  DeviceActionResponse,
  DeviceRecord,
  AddManualDeviceRequest,
  DevicePatchRequest,
  RejectDeviceRequest,
  FirmwareAssessmentStatus,
  FirmwareEvidenceSource,
  FirmwareAssessment,
  DeviceScanProgressTransition,
  DeviceScanRun,
} from './managedDeviceService';

export type {
  Paginated as SmartHomePaginated,
  SmartDevice,
  DeviceListFilters,
  DeviceStateSnapshot,
  DeviceCommandRequest,
  DeviceCommandResponse,
  DeviceSyncResponse,
  DeviceHealthSummary,
  AutomationTrigger,
  AutomationAction,
  AutomationRule,
  AutomationListFilters,
  AutomationMutationResponse,
  TelemetryEvent,
  TelemetryFilters,
  SmartHomeNotification,
  NotificationFilters,
  MarkNotificationsReadResponse,
  IntegrationProvider,
  IntegrationStatus,
  IntegrationsOverview,
  ConnectOAuthProviderRequest,
  ConnectKasaRequest,
  ConnectIntegrationRequest,
  ConnectIntegrationResponse,
  DisconnectIntegrationResponse,
  SmartHomeTopic,
  SmartHomeSocketEvent,
} from './smartHomeService';

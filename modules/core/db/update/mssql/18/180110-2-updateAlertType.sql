alter table ALERTSYSTEM_ALERT_TYPE add FROM_PROCESS_TYPE integer ^
update ALERTSYSTEM_ALERT_TYPE set FROM_PROCESS_TYPE = 0 where FROM_PROCESS_TYPE is null ;
alter table ALERTSYSTEM_ALERT_TYPE alter column FROM_PROCESS_TYPE integer not null ;
alter table ALERTSYSTEM_ALERT_TYPE add TO_PROCESS_TYPE integer ^
update ALERTSYSTEM_ALERT_TYPE set TO_PROCESS_TYPE = 0 where TO_PROCESS_TYPE is null ;
alter table ALERTSYSTEM_ALERT_TYPE alter column TO_PROCESS_TYPE integer not null ;

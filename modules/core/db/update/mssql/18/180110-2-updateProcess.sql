alter table ALERTSYSTEM_PROCESS add TYPE integer ^
update ALERTSYSTEM_PROCESS set TYPE = 0 where TYPE is null ;
alter table ALERTSYSTEM_PROCESS alter column TYPE integer not null ;

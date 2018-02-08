-- begin ALERTSYSTEM_ALERT_SNOOZE
create table ALERTSYSTEM_ALERT_SNOOZE (
    ID uniqueidentifier,
    CREATE_TS datetime,
    CREATED_BY varchar(50),
    --
    SAMPLE_ORDER_ID integer not null,
    ALERT_TYPE_ID integer,
    DURATION integer,
    --
    primary key nonclustered (ID)
)^
-- end ALERTSYSTEM_ALERT_SNOOZE
-- begin ALERTSYSTEM_ALERT_TYPE
create table ALERTSYSTEM_ALERT_TYPE (
    ID integer,
    --
    FROM_PROCESS_ID integer,
    FROM_PROCESS_TYPE integer not null,
    TO_PROCESS_ID integer,
    TO_PROCESS_TYPE integer not null,
    ALLOWED_DURATION integer,
    SINGLE_MAX_DURATION integer,
    TOTAL_MAX_DURATION integer,
    --
    primary key (ID)
)^
-- end ALERTSYSTEM_ALERT_TYPE
-- begin ALERTSYSTEM_PROCESS
create table ALERTSYSTEM_PROCESS (
    ID integer,
    --
    NAME varchar(255),
    ZT_WORKING_ID integer,
    --
    primary key (ID)
)^
-- end ALERTSYSTEM_PROCESS

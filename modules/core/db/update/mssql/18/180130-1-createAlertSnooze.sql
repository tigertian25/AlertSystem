create table ALERTSYSTEM_ALERT_SNOOZE (
    ID integer,
    CREATE_TS datetime,
    CREATED_BY varchar(50),
    --
    SAMPLE_ORDER_ID integer not null,
    ALERT_TYPE_ID integer,
    DURATION integer,
    --
    primary key (ID)
);

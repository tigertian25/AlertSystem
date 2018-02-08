create table ALERTSYSTEM_ALERT_TYPE (
    ID integer,
    --
    FROM_PROCESS_ID integer,
    TO_PROCESS_ID integer,
    ALLOWED_DURATION integer,
    SINGLE_MAX_DURATION integer,
    TOTAL_MAX_DURATION integer,
    --
    primary key (ID)
);

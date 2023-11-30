-- ceode to create vulnerabillites table
CREATE TABLE IF NOT EXISTS public.vulnerabilities
(
    id integer NOT NULL GENERATED ALWAYS AS IDENTITY ( INCREMENT 1 START 1 MINVALUE 1 MAXVALUE 2147483647 CACHE 1 ),
    cveid text COLLATE pg_catalog."default",
    dateupdated text COLLATE pg_catalog."default",
    vendor text COLLATE pg_catalog."default",
    product text COLLATE pg_catalog."default",
    versions text COLLATE pg_catalog."default",
    description text COLLATE pg_catalog."default",
    reference text COLLATE pg_catalog."default",
    confidentialityimpact text COLLATE pg_catalog."default",
    integrityimpact text COLLATE pg_catalog."default",
    availabilityimpact text COLLATE pg_catalog."default",
    basescore text COLLATE pg_catalog."default",
    baseseverity text COLLATE pg_catalog."default",
    CONSTRAINT vulnerabilities_pkey PRIMARY KEY (id)
);

-- code to create scans table
CREATE TABLE IF NOT EXISTS public.scans
(
    id integer NOT NULL GENERATED ALWAYS AS IDENTITY ( INCREMENT 1 START 1 MINVALUE 1 MAXVALUE 2147483647 CACHE 1 ),
    scan_name text COLLATE pg_catalog."default",
    system_ip text COLLATE pg_catalog."default",
    username text COLLATE pg_catalog."default",
    shared_with text COLLATE pg_catalog."default",
    scan_date text COLLATE pg_catalog."default",
    current_status text COLLATE pg_catalog."default",
    CONSTRAINT scans_pkey PRIMARY KEY (id)
)

-- code to create findings table
CREATE TABLE IF NOT EXISTS public.findings
(
    id integer NOT NULL GENERATED ALWAYS AS IDENTITY ( INCREMENT 1 START 1 MINVALUE 1 MAXVALUE 2147483647 CACHE 1 ),
    cveid text COLLATE pg_catalog."default",
    scan_id integer,
    infected_service text COLLATE pg_catalog."default",
    CONSTRAINT findings_pkey PRIMARY KEY (id)
)

-- code for searching vulnerabillites through api
CREATE TABLE IF NOT EXISTS public.api_result
(
    id integer NOT NULL GENERATED ALWAYS AS IDENTITY ( INCREMENT 1 START 1 MINVALUE 1 MAXVALUE 2147483647 CACHE 1 ),
    description text COLLATE pg_catalog."default",
    nvd text COLLATE pg_catalog."default",
    refrences text COLLATE pg_catalog."default",
    cve_id text COLLATE pg_catalog."default",
    infected_service text COLLATE pg_catalog."default",
    scan_id integer,
    impact text COLLATE pg_catalog."default"
)

-- create scan result table
CREATE TABLE IF NOT EXISTS public.netowrk_scan_result
(
    id integer NOT NULL GENERATED ALWAYS AS IDENTITY ( INCREMENT 1 START 1 MINVALUE 1 MAXVALUE 2147483647 CACHE 1 ),
    scan_id integer,
    svc text COLLATE pg_catalog."default",
	svc_product text COLLATE pg_catalog."default",
	svc_ver text COLLATE pg_catalog."default",
	port_number text COLLATE pg_catalog."default",
	script text COLLATE pg_catalog."default",
    CONSTRAINT netowrk_scan_result_pkey PRIMARY KEY (id)
)
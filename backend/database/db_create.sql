
CREATE TABLE public.api_result (
    id integer NOT NULL,
    description text,
    nvd text,
    refrences text,
    cve_id text,
    infected_service text,
    scan_id integer,
    impact text,
    port_number text
);


CREATE TABLE public.findings (
    id integer NOT NULL,
    cveid text,
    scan_id integer,
    infected_service text,
    port_number text,
    is_easy boolean,
    exploit_links text
);



CREATE TABLE public.netowrk_scan_result (
    id integer NOT NULL,
    scan_id integer,
    svc text,
    svc_product text,
    svc_ver text,
    port_number text,
    script text
);


CREATE TABLE public.scans (
    id integer NOT NULL,
    scan_name text,
    system_ip text,
    username text,
    shared_with text,
    scan_date text,
    current_status text,
    scan_type text,
    is_runscript text
);



CREATE TABLE public.vulnerabilities (
    id integer NOT NULL,
    dateupdated text,
    vendor text,
    product text,
    versions text,
    description text,
    confidentialityimpact text,
    integrityimpact text,
    availabilityimpact text,
    baseseverity text,
    basescore text,
    reference text,
    cveid text
);



CREATE TABLE public.vulns (
    "dataType" text,
    "dataVersion" bigint,
    "cveMetadata" text,
    containers text
);

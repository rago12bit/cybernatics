"""The advisory engine (plan §46.2, §55.5): OSV, CISA KEV and NVD fetched on a schedule
(`feeds`, `store`), matched against the component inventory the way osv-scanner matches
(`osv`, `impact`), read as the morning list and one advisory's impact view (`view`), and turned into
Issues and tickets in one click (`issues`)."""

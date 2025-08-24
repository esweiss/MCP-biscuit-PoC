-- POLICY: patient_data_policy

-- DROP POLICY IF EXISTS patient_data_policy ON public.health_records;

CREATE POLICY patient_data_policy
    ON public.health_records
    AS PERMISSIVE
    FOR ALL
    TO patients
    USING ((("Patient Name")::text = current_setting('patient_name'::text)));

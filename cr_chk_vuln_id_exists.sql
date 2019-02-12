-- Run cr_chk_vuln_id_exists.sql
create or replace FUNCTION chk_vuln_id_exists (pv_vuln_id IN VARCHAR2)
   RETURN BOOLEAN IS
   lv_data XMLType;
   BEGIN
   SELECT XMLQuery('for $j in $obj/CHECKLIST/STIGS/iSTIG/VULN
                let $status := $j/STATUS
                where $j/STIG_DATA[1]/ATTRIBUTE_DATA = $pv_vuln
                return $status' PASSING OBJECT_VALUE as "obj",
                pv_vuln_id as "pv_vuln"  RETURNING CONTENT)
                INTO lv_data
   FROM ora12c_chklist_xml;

   IF lv_data IS NULL THEN
      dbms_output.put_line('FALSE');
      RETURN FALSE;
   ELSE
      dbms_output.put_line('TRUE');
      RETURN TRUE;
   END IF;

END chk_vuln_id_exists;

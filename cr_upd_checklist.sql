-- Run cr_upd_checklist.sql
create or replace PROCEDURE update_checklist ( pv_vuln_id IN VARCHAR2, pv_status IN VARCHAR2, pv_details IN VARCHAR2) AS
   lv_stmt varchar2(8000);
   BEGIN
   IF chk_vuln_id_exists(pv_vuln_id) THEN
      lv_stmt := q'[UPDATE ora12c_chklist_xml
				SET OBJECT_VALUE = XMLQUERY(
                 'copy $newxml := $obj modify 
					(
						for $j in $newxml/CHECKLIST/STIGS/iSTIG/VULN			
						where $j/STIG_DATA[1]/ATTRIBUTE_DATA = $vulnid
						return 
						(
							replace value of node $j/STATUS with $vstatus,
							replace value of node $j/FINDING_DETAILS with $vdetails
						)
					)
				return $newxml' PASSING OBJECT_VALUE as "obj",
                :1 as "vulnid",
				:2 as "vstatus",
				:3 as "vdetails"
				RETURNING CONTENT
				)
				WHERE XMLExists('$xml/CHECKLIST/STIGS/iSTIG/VULN/STIG_DATA[1]/ATTRIBUTE_DATA = $vulnid '
				PASSING OBJECT_VALUE as "xml",
                :4 as "vulnid"
                ) ]' ;
				EXECUTE IMMEDIATE lv_stmt USING pv_vuln_id, pv_status, pv_details, pv_vuln_id;
        commit;
        dbms_output.put_line('Updated and committed!');
    ELSE
        dbms_output.put_line('Vulnerability does not exist.');
    END IF;
END update_checklist;

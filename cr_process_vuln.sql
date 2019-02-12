CREATE OR REPLACE PROCEDURE CSRRUSER.chk_61411 (pv_vuln_id IN VARCHAR2)
AS
    CURSOR cv_chk_v61411 IS
          SELECT COUNT (*) AS cnt, owner
            FROM all_tables
           WHERE table_name LIKE 'REPCAT%'
        GROUP BY owner;


    /*CURSOR cv_chk_v61411 IS
          SELECT COUNT (sysdate) as cnt, 'owner' as owner
            FROM dual;
    */


    lv_owner             all_tables.owner%TYPE;
    lv_chk_rec           cv_chk_v61411%ROWTYPE;
    lv_number            NUMBER := 0;
    lv_finding_details   VARCHAR2 (2000) := '';
    lv_status            VARCHAR2 (25) := '';
    lv_cnt_is_zero       BOOLEAN := FALSE;
BEGIN
    INSERT INTO log_table (MESSAGE, date_time, seq)
         VALUES ('In procedure check_V_61411:  '||pv_vuln_id, SYSDATE, 1);

    COMMIT;

    --    DBMS_OUTPUT.put_line ('In procedure check_V_61411 ');

    OPEN cv_chk_v61411;

    LOOP
        FETCH cv_chk_v61411 INTO lv_chk_rec;

        IF lv_chk_rec.cnt IS NULL
        THEN
            lv_cnt_is_zero := TRUE;
            EXIT WHEN lv_cnt_is_zero;
        END IF;

        EXIT WHEN cv_chk_v61411%NOTFOUND;

        --        DBMS_OUTPUT.put_line (
        --            'Count: ' || lv_chk_rec.cnt || ' owner: ' || lv_chk_rec.owner);

        INSERT INTO log_table (MESSAGE, date_time, seq)
                 VALUES (
                        'Count: '
                     || lv_chk_rec.cnt
                     || ' owner: '
                     || lv_chk_rec.owner,
                     SYSDATE,
                     2);

        COMMIT;

        --        DBMS_OUTPUT.put_line ('This is a finding.');

        INSERT INTO log_table (MESSAGE, date_time, seq)
             VALUES ('This is a finding.', SYSDATE, 3);

        COMMIT;
        lv_finding_details :=
               'This is a finding.  The check found owner: '
            || lv_chk_rec.owner
            || ' has this many objects: '
            || lv_chk_rec.cnt
            || ' '
            || lv_finding_details;
        lv_status := 'Open';
    END LOOP;

    CLOSE cv_chk_v61411;

    IF lv_cnt_is_zero
    THEN
        --        DBMS_OUTPUT.put_line ('Not a finding. There are no objects found.');
        lv_finding_details := 'Not a finding. There are no objects found';
        lv_status := 'Not_A_Finding';

        INSERT INTO log_table (MESSAGE, date_time, seq)
                 VALUES (lv_finding_details||' : '||pv_vuln_id,
                         SYSDATE,
                         4);

        COMMIT;

        
    END IF;

    update_checklist (pv_vuln_id, lv_status, lv_finding_details);
END chk_61411;
/

from flask import (
    Flask, render_template, request, session, redirect,
    url_for, flash, send_from_directory, jsonify, abort
)
import os
from werkzeug.utils import secure_filename
import sqlite3
from db_manager import (
    create_main_db, add_vulnerability, get_all_vulnerabilities,
    get_vulnerability_by_name, get_company_list, add_company,
    create_company_db, add_or_append_company_data,
    get_vuln_data_for_company, get_vulnerability_by_id,
    update_vulnerability, delete_vulnerability_by_id,
    delete_company_db_and_data, delete_company_vuln,
    get_all_company_vulns, get_vuln_data_for_report,
    get_company_classes, add_company_class,
    VULN_DB, MAIN_MASTER_DB,
)
from report_generator import generate_word_report

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev_secret_key")

VAPT_TYPES = ["Web", "Network", "Mobile", "API"]
SEVERITY_TYPES = ["Critical", "High", "Medium", "Low", "Informational"]
UPLOAD_FOLDER = "evidence_uploads"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "pdf", "txt"}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def is_valid_cvss_input(cvss_str, severity):
    """
    Returns (bool, error_message)
    Rules:
        - If severity is Informational:
            - Allow blank, or value between 0 and 10
        - Else:
            - Must be a number and 0 <= cvss <= 10
    """
    INFORM = (severity or "").lower().strip() == "informational"
    if (cvss_str is None or cvss_str.strip() == ""):
        if INFORM:
            return True, None  # Allowed empty for Informational
        else:
            return False, "CVSS Score is required for selected severity."
    try:
        score = float(cvss_str)
        if 0 <= score <= 10:
            return True, None
        else:
            return False, "CVSS Score must be a number between 0 and 10."
    except Exception:
        return False, "CVSS Score must be a valid number."

create_main_db(MAIN_MASTER_DB)

def migrate_company_dbs():
    for company in get_company_list():
        try:
            create_company_db(company)
        except Exception as e:
            print(f"[migrate] {company}: {e}")

migrate_company_dbs()

@app.context_processor
def inject_theme():
    return {"dark_mode": session.get("theme") == "dark"}

@app.route("/", methods=["GET"])
def index():
    companies = get_company_list()
    return render_template("index.html", companies=companies)

@app.route("/add_company", methods=["POST"])
def add_company_route():
    company_name = (request.form.get("company_name") or "").strip()
    if not company_name:
        flash("Company name cannot be empty.", "error")
    elif company_name in get_company_list():
        flash("Company already exists.", "error")
    else:
        add_company(MAIN_MASTER_DB, company_name)
        flash(f"Company '{company_name}' added successfully!", "success")
    return redirect(url_for("index"))

@app.route("/delete_company", methods=["POST"])
def delete_company():
    company_name = request.form.get("company_name", "").strip()
    confirm_name = request.form.get("confirm_name", "").strip()
    if not company_name:
        flash("Company name missing.", "error")
        return redirect(url_for("index"))
    if confirm_name != company_name:
        flash("Confirmation name does not match. Deletion cancelled.", "error")
        return redirect(url_for("index"))
    if company_name in get_company_list():
        delete_company_db_and_data(company_name)
        flash(f"Company '{company_name}' has been deleted successfully.", "success")
    else:
        flash("Company not found.", "error")
    return redirect(url_for("index"))

@app.route("/delete_company/<company>", methods=["GET"])
def confirm_delete_company(company):
    if company not in get_company_list():
        flash("Company not found.", "error")
        return redirect(url_for("index"))
    return render_template("delete_company_confirm.html", company=company)

@app.route("/view_vulns", methods=["GET"])
def view_vulns():
    vulns = get_all_vulnerabilities(VULN_DB)
    return render_template("view_vulns.html", vulns=vulns)

@app.route("/add_vulnerability", methods=["GET", "POST"])
def add_vulnerability_route():
    if request.method == "POST":
        name = request.form.get("name")
        vapt_type = request.form.get("vapt_type")
        severity = request.form.get("severity")
        cvss_score = request.form.get("cvss_score")
        description = request.form.get("description")
        impact = request.form.get("impact")
        remediation = request.form.get("remediation")
        references_text = request.form.get("references_text")

        is_valid, err = is_valid_cvss_input(cvss_score, severity)
        if not is_valid:
            flash(err, "error")
            return redirect(url_for("add_vulnerability_route"))

        add_vulnerability(
            db_file=VULN_DB,
            name=name,
            vapt_type=vapt_type,
            severity=severity,
            cvss_score=cvss_score if cvss_score else None,
            description=description,
            impact=impact,
            remediation=remediation,
            references_text=references_text,
        )
        flash("Vulnerability added successfully!", "success")
        return redirect(url_for("view_vulns"))
    return render_template(
        "add_vulnerability.html",
        vapt_types=VAPT_TYPES,
        severity_types=SEVERITY_TYPES,
    )

@app.route("/edit_vulnerability/<int:vuln_id>", methods=["GET", "POST"])
def edit_vulnerability(vuln_id):
    vuln = get_vulnerability_by_id(VULN_DB, vuln_id)
    if not vuln:
        flash("Vulnerability not found.", "error")
        return redirect(url_for("view_vulns"))
    if request.method == "POST":
        name = request.form.get("name")
        vapt_type = request.form.get("vapt_type")
        severity = request.form.get("severity")
        cvss_score = request.form.get("cvss_score")
        description = request.form.get("description")
        impact = request.form.get("impact")
        remediation = request.form.get("remediation")
        references_text = request.form.get("references_text")

        is_valid, err = is_valid_cvss_input(cvss_score, severity)
        if not is_valid:
            flash(err, "error")
            return redirect(url_for("edit_vulnerability", vuln_id=vuln_id))

        update_vulnerability(
            db_file=VULN_DB,
            vuln_id=vuln_id,
            name=name,
            vapt_type=vapt_type,
            severity=severity,
            cvss_score=cvss_score if cvss_score else None,
            description=description,
            impact=impact,
            remediation=remediation,
            references_text=references_text,
        )
        flash("Vulnerability updated successfully!", "success")
        return redirect(url_for("view_vulns"))
    return render_template(
        "edit_vulnerability.html",
        vuln=vuln,
        vapt_types=VAPT_TYPES,
        severity_types=SEVERITY_TYPES,
    )

@app.route("/companies/<company>/add_target_first", methods=["GET", "POST"])
def add_target_first(company):
    if company not in get_company_list():
        abort(404)

    master_vulns = get_all_vulnerabilities(VULN_DB)
    classes = get_company_classes(company)

    if request.method == "POST":
        target_ip = (request.form.get("target_ip") or "").strip()
        target_class = (request.form.get("target_class") or "").strip()

        # Arrays for multiple vuln rows (same index across fields)
        vuln_ids = request.form.getlist("vuln_id[]")
        ports = request.form.getlist("port[]")

        # Evidence per-row: files and texts
        # Note: Flask doesn't support getlist on files; name files uniquely per row: evidence_file_0, evidence_file_1, ...
        # We'll read a hidden count field to iterate indexes
        row_count = int(request.form.get("row_count") or "0")

        if not target_ip:
            flash("Target IP address is required.", "error")
            return redirect(url_for("add_target_first", company=company))

        if not target_class:
            flash("Target class is required.", "error")
            return redirect(url_for("add_target_first", company=company))

        # Validate at least one valid row (vuln selected and some evidence provided per row)
        any_valid = False
        for i in range(row_count):
            vid = (vuln_ids[i] if i < len(vuln_ids) else "").strip()
            ev_text = (request.form.get(f"evidence_text_{i}") or "").strip()
            ev_file = request.files.get(f"evidence_file_{i}")
            if vid and (ev_text or (ev_file and allowed_file(ev_file.filename))):
                any_valid = True
                break

        if not any_valid:
            flash("Please add at least one vulnerability with evidence (file or text).", "error")
            return redirect(url_for("add_target_first", company=company))

        # Process each row
        for i in range(row_count):
            vid = (vuln_ids[i] if i < len(vuln_ids) else "").strip()
            if not vid:
                continue

            port = (ports[i] if i < len(ports) else "").strip()
            vuln_info = get_vulnerability_by_id(VULN_DB, int(vid))
            if not vuln_info:
                continue

            # Resolve per-row evidence
            ev_text = (request.form.get(f"evidence_text_{i}") or "").strip()
            ev_file = request.files.get(f"evidence_file_{i}")
            evidence = ev_text

            if ev_file and allowed_file(ev_file.filename):
                filename = secure_filename(ev_file.filename)
                upload_dir = os.path.join(app.config["UPLOAD_FOLDER"], company)
                os.makedirs(upload_dir, exist_ok=True)
                upload_path = os.path.join(upload_dir, filename)
                ev_file.save(upload_path)
                evidence = os.path.relpath(upload_path, start=app.config["UPLOAD_FOLDER"])

            if not evidence:
                # Skip a row without any evidence
                continue

            target_str = f"{target_ip}:{port}" if port else target_ip

            # For each vulnerability row, append/update this vuln with its own evidence and the one target/class/port tuple
            add_or_append_company_data(
                company=company,
                vuln_id=int(vid),
                vuln_name=vuln_info.name,
                severity=vuln_info.severity,
                vapt_type=vuln_info.vapt_type,
                evidence=evidence,
                targets_info=[(target_str, target_class, port)],
            )

        flash("Target and vulnerabilities added successfully.", "success")
        return redirect(url_for("view_target_vulns_route", company=company))

    return render_template(
        "add_target_first.html",
        company=company,
        master_vulns=master_vulns,
        classes=classes,
    )


@app.route("/delete_vulnerability/<int:vuln_id>", methods=["POST"])
def delete_vulnerability(vuln_id):
    vuln_info = get_vulnerability_by_id(VULN_DB, vuln_id)
    if not vuln_info:
        flash("Vulnerability not found.", "error")
        return redirect(url_for("view_vulns"))
    try:
        delete_vulnerability_by_id(VULN_DB, vuln_id)
        flash(f"Vulnerability '{vuln_info.name}' deleted successfully!", "success")
    except Exception as e:
        flash(f"Error deleting vulnerability: {e}", "error")
    return redirect(url_for("view_vulns"))

@app.route("/companies/<company>", methods=["GET"])
def view_target_vulns_route(company):
    if company not in get_company_list():
        abort(404)
    vulns = get_all_company_vulns(company)
    return render_template("view_target_vulns.html", company=company, vulns=vulns)

@app.route("/companies/<company>/add_vuln", methods=["GET", "POST"])
def add_vuln_to_company(company):
    if company not in get_company_list():
        abort(404)

    if request.method == "POST":
        vuln_id = request.form.get("vuln_id")

        targets_info = []
        target_names = request.form.getlist("target_name")
        target_classes = request.form.getlist("target_class")
        target_ports = request.form.getlist("target_port")  # optional

        for i, (name, cls) in enumerate(zip(target_names, target_classes)):
            if name.strip():
                port = target_ports[i].strip() if i < len(target_ports) else ""
                targets_info.append((name.strip(), (cls or "").strip(), port))  # 3-tuple

        evidence_file = request.files.get("evidence_file")
        evidence_text = request.form.get("evidence_text")
        evidence = evidence_text

        if evidence_file and allowed_file(evidence_file.filename):
            filename = secure_filename(evidence_file.filename)
            upload_path = os.path.join(app.config["UPLOAD_FOLDER"], company, filename)
            os.makedirs(os.path.dirname(upload_path), exist_ok=True)
            evidence_file.save(upload_path)
            evidence = os.path.relpath(upload_path, start=UPLOAD_FOLDER)

        if not vuln_id or not targets_info or not (evidence_file or evidence_text):
            flash("Vulnerability, at least one target, and evidence are required.", "error")
            return redirect(url_for("add_vuln_to_company", company=company))

        vuln_info = get_vulnerability_by_id(VULN_DB, int(vuln_id))
        if not vuln_info:
            flash("Vulnerability not found.", "error")
            return redirect(url_for("add_vuln_to_company", company=company))

        add_or_append_company_data(
            company=company,
            vuln_id=int(vuln_id),
            vuln_name=vuln_info.name,
            severity=vuln_info.severity,
            vapt_type=vuln_info.vapt_type,
            evidence=evidence,
            targets_info=targets_info,  # list of (target, class, port)
        )

        flash("Vulnerability added to company successfully!", "success")
        return redirect(url_for("view_target_vulns_route", company=company))

    master_vulns = get_all_vulnerabilities(VULN_DB)
    classes = get_company_classes(company)
    return render_template(
        "add_company_vuln.html",
        company=company,
        vulns=master_vulns,
        classes=classes,
    )

@app.route("/companies/<company>/edit_vuln/<int:vuln_id>", methods=["GET", "POST"])
def edit_company_vuln(company, vuln_id):
    if company not in get_company_list():
        abort(404)

    vuln_data, targets = get_vuln_data_for_company(company, vuln_id)
    if not vuln_data:
        flash("Vulnerability not found.", "error")
        return redirect(url_for("view_target_vulns_route", company=company))

    if request.method == "POST":
        targets_info = []
        target_names = request.form.getlist("target_name")
        target_classes = request.form.getlist("target_class")
        target_ports = request.form.getlist("target_port")  # optional

        for i, (name, cls) in enumerate(zip(target_names, target_classes)):
            if name.strip():
                port = target_ports[i].strip() if i < len(target_ports) else ""
                targets_info.append((name.strip(), (cls or "").strip(), port))  # 3-tuple

        evidence_file = request.files.get("evidence_file")
        evidence_text = request.form.get("evidence_text")
        current_evidence = vuln_data[4]  # from company_vulns: cvss_score at [4] in your current schema; adjust if needed
        evidence = current_evidence

        if evidence_file and allowed_file(evidence_file.filename):
            filename = secure_filename(evidence_file.filename)
            upload_path = os.path.join(app.config["UPLOAD_FOLDER"], company, filename)
            os.makedirs(os.path.dirname(upload_path), exist_ok=True)
            evidence_file.save(upload_path)
            evidence = os.path.relpath(upload_path, start=UPLOAD_FOLDER)
        elif evidence_text:
            evidence = evidence_text

        add_or_append_company_data(
            company=company,
            vuln_id=vuln_id,
            vuln_name=vuln_data[1],
            severity=vuln_data[2],
            vapt_type=vuln_data[3],
            evidence=evidence,
            targets_info=targets_info,  # list of (target, class, port)
        )

        flash("Vulnerability updated successfully!", "success")
        return redirect(url_for("view_target_vulns_route", company=company))

    classes = get_company_classes(company)
    return render_template(
        "edit_company_vuln.html",
        company=company,
        vuln_data=vuln_data,
        targets=targets,
        classes=classes,
    )

@app.route("/companies/<company>/delete_vuln/<int:vuln_id>", methods=["POST"])
def delete_company_vuln_route(company, vuln_id):
    if company not in get_company_list():
        abort(404)
    delete_company_vuln(company, vuln_id)
    flash("Vulnerability deleted successfully!", "success")
    return redirect(url_for("view_target_vulns_route", company=company))

@app.route("/companies/<company>/build_report", methods=["GET", "POST"])
def build_report(company):
    if company not in get_company_list():
        abort(404)
    if request.method == "POST":
        vapt_type = (request.form.get("vapt_type") or "").strip()
        if not vapt_type:
            flash("Please select a VAPT type.", "error")
            return redirect(url_for("build_report", company=company))
        vulns_data, targets_data = get_vuln_data_for_report(company, vapt_type)
        return render_template(
            "report_preview.html",
            company=company,
            vulns=vulns_data,
            targets=targets_data,
            vapt_type=vapt_type,
        )
    return render_template("build_report.html", company=company, vapt_types=VAPT_TYPES)

@app.route("/companies/<company>/download_report", methods=["GET"])
def download_report(company):
    if company not in get_company_list():
        abort(404)
    vapt_type = (request.args.get("vapt_type") or "").strip()
    if not vapt_type:
        flash("VAPT type is required.", "error")
        return redirect(url_for("build_report", company=company))
    # get_vuln_data_for_report returns (dict_of_vulns, dict_of_targets)
    vulns_dict, targets = get_vuln_data_for_report(company, vapt_type)
    # Convert to list of (id, dict) tuples as expected by generator
    vulns_list = list(vulns_dict.items())
    output_path = os.path.join("reports", f"{company}_VAPT_Report_{vapt_type}.docx")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    generate_word_report(company, vulns_list, targets, output_path)
    return send_from_directory(
        os.path.dirname(output_path),
        os.path.basename(output_path),
        as_attachment=True,
    )

@app.route("/evidence/<path:relpath>")
def evidence_file(relpath):
    full_path = os.path.join(app.config["UPLOAD_FOLDER"], relpath)
    base = os.path.abspath(app.config["UPLOAD_FOLDER"])
    full_abs = os.path.abspath(full_path)
    if not full_abs.startswith(base):
        abort(403)
    return send_from_directory(
        os.path.dirname(full_abs), os.path.basename(full_abs)
    )

@app.route("/toggle_theme", methods=["POST"])
def toggle_theme():
    session["theme"] = "dark" if session.get("theme") != "dark" else "light"
    return jsonify({"theme": session.get("theme")})

def _get_relative_path(path):
    return os.path.relpath(path, start=app.config["UPLOAD_FOLDER"])

@app.route("/companies/<company>/manage_classes", methods=["GET", "POST"])
def manage_classes(company):
    if company not in get_company_list():
        abort(404)
    classes = get_company_classes(company)
    if request.method == "POST":
        new_class = (request.form.get("new_class") or "").strip()
        if not new_class:
            flash("Class name cannot be empty.", "error")
        else:
            add_company_class(company, new_class)
            flash(f'Class "{new_class}" added.', "success")
        return redirect(url_for("manage_classes", company=company))
    return render_template("manage_classes.html", company=company, classes=classes)

@app.route("/companies/<company>/delete_class", methods=["POST"])
def delete_class(company):
    if company not in get_company_list():
        abort(404)
    class_name = request.form.get("class_name")
    if not class_name:
        flash("Class name is required to delete.", "error")
        return redirect(url_for("manage_classes", company=company))
    db_file = f"{company}.db"
    conn = sqlite3.connect(db_file)
    try:
        c = conn.cursor()
        c.execute("DELETE FROM company_classes WHERE class_name = ?", (class_name,))
        conn.commit()
        flash(f'Class "{class_name}" deleted.', "success")
    except sqlite3.Error as e:
        flash(f"Database error: {e}", "error")
    finally:
        conn.close()
    return redirect(url_for("manage_classes", company=company))

@app.route("/companies/<company>/search_target", methods=["GET"])
def search_target_vulns(company):
    if company not in get_company_list():
        abort(404)
    target_name = (request.args.get("target", "")).strip()
    if not target_name:
        flash("Target name cannot be empty.", "error")
        return redirect(url_for("view_target_vulns_route", company=company))
    vulns = get_all_company_vulns(company)
    found_vulns = []
    for vuln in vulns:
        if any(target_name.lower() in (t[0] or "").lower() for t in vuln.get("targets", [])):
            found_vulns.append(vuln)
    return render_template(
        "target_search_results.html",
        company=company,
        target=target_name,
        vulns=found_vulns,
    )

if __name__ == "__main__":
    app.run(debug=True)

import docx

from api_requests import parse_vuln_info, get_vuln_info, get_description


# Récupérer les informations de la CVE
CVE_NAME = str(input("Entrez le nom de la CVE: "))

affected_devices = parse_vuln_info(get_vuln_info(CVE_NAME))
description = get_description(CVE_NAME)

# Création du document Word
report = docx.Document()

# Ajour du titre du rapport
report.add_heading(f"Rapport pour la {CVE_NAME}", 0)

# Présenter les informations des machines impactées
report.add_heading(f"{len(affected_devices)} machine(s) impactée(s)", level=1)
report.add_paragraph("Tableau des machines impactées par la CVE")

# Création du tableau
table = report.add_table(rows=1, cols=4)
table.style = "Table Grid"

# Ajout des en-têtes
hdr_cells = table.rows[0].cells
hdr_cells[0].text = "Instance"
hdr_cells[1].text = "IP"
hdr_cells[2].text = "Profile"
hdr_cells[3].text = "Site"

# Ajout des données au tableau
for key, value in affected_devices.items():
    row_cells = table.add_row().cells
    row_cells[0].text = key
    row_cells[1].text = ", ".join([item[0] for item in value])
    row_cells[2].text = ", ".join([item[1] for item in value])
    row_cells[3].text = ", ".join([item[2] for item in value])

# Ajout de la description de la CVE
report.add_heading("Description de la CVE", level=1)
report.add_paragraph(description)

report.add_heading("Solution(s) à mettre en place", level=1)

# Enregistrement du rapport
docx_path = f"./reports/{CVE_NAME}_report.docx"
report.save(docx_path)

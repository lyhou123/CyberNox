"""
Report generation module for CyberNox
"""

import json
import csv
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from utils.logger import logger
from utils.config import config

class ReportGenerator:
    """Generate reports in various formats"""
    
    def __init__(self):
        self.output_format = config.get('general.output_format', 'json')
        self.reports_dir = Path("reports")
        self.reports_dir.mkdir(exist_ok=True)
    
    def generate_scan_report(self, scan_results, output_file=None):
        """Generate comprehensive scan report"""
        logger.info("Generating scan report")
        
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.reports_dir / f"cybernox_scan_{timestamp}"
        
        # Prepare report data
        report_data = {
            "metadata": {
                "tool": "CyberNox",
                "version": "1.0.0",
                "scan_date": datetime.now().isoformat(),
                "report_type": "Security Scan Report"
            },
            "summary": self._generate_summary(scan_results),
            "results": scan_results
        }
        
        # Generate report in requested format
        if self.output_format.lower() == 'json':
            return self._generate_json_report(report_data, f"{output_file}.json")
        elif self.output_format.lower() == 'xml':
            return self._generate_xml_report(report_data, f"{output_file}.xml")
        elif self.output_format.lower() == 'csv':
            return self._generate_csv_report(report_data, f"{output_file}.csv")
        elif self.output_format.lower() == 'html':
            return self._generate_html_report(report_data, f"{output_file}.html")
        else:
            return self._generate_text_report(report_data, f"{output_file}.txt")
    
    def _generate_summary(self, scan_results):
        """Generate summary of scan results"""
        summary = {
            "total_targets": 0,
            "vulnerabilities_found": 0,
            "critical_issues": 0,
            "high_issues": 0,
            "medium_issues": 0,
            "low_issues": 0,
            "info_issues": 0
        }
        
        # Count different types of findings
        if isinstance(scan_results, list):
            for result in scan_results:
                if isinstance(result, dict):
                    if 'vulnerabilities' in result:
                        vulns = result['vulnerabilities']
                        if isinstance(vulns, list):
                            summary['vulnerabilities_found'] += len(vulns)
                            for vuln in vulns:
                                severity = vuln.get('severity', 'Low').lower()
                                if severity == 'critical':
                                    summary['critical_issues'] += 1
                                elif severity == 'high':
                                    summary['high_issues'] += 1
                                elif severity == 'medium':
                                    summary['medium_issues'] += 1
                                elif severity == 'low':
                                    summary['low_issues'] += 1
                                else:
                                    summary['info_issues'] += 1
        
        return summary
    
    def _generate_json_report(self, report_data, output_file):
        """Generate JSON report"""
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"JSON report generated: {output_file}")
            return {"status": "success", "file": str(output_file), "format": "JSON"}
            
        except Exception as e:
            error_msg = f"Failed to generate JSON report: {e}"
            logger.error(error_msg)
            return {"status": "error", "message": error_msg}
    
    def _generate_xml_report(self, report_data, output_file):
        """Generate XML report"""
        try:
            root = ET.Element("cybernox_report")
            
            # Add metadata
            metadata = ET.SubElement(root, "metadata")
            for key, value in report_data["metadata"].items():
                elem = ET.SubElement(metadata, key)
                elem.text = str(value)
            
            # Add summary
            summary = ET.SubElement(root, "summary")
            for key, value in report_data["summary"].items():
                elem = ET.SubElement(summary, key)
                elem.text = str(value)
            
            # Add results
            results = ET.SubElement(root, "results")
            self._dict_to_xml(report_data["results"], results)
            
            # Write to file
            tree = ET.ElementTree(root)
            tree.write(output_file, encoding='utf-8', xml_declaration=True)
            
            logger.info(f"XML report generated: {output_file}")
            return {"status": "success", "file": str(output_file), "format": "XML"}
            
        except Exception as e:
            error_msg = f"Failed to generate XML report: {e}"
            logger.error(error_msg)
            return {"status": "error", "message": error_msg}
    
    def _dict_to_xml(self, data, parent):
        """Convert dictionary to XML elements"""
        if isinstance(data, dict):
            for key, value in data.items():
                elem = ET.SubElement(parent, str(key))
                self._dict_to_xml(value, elem)
        elif isinstance(data, list):
            for item in data:
                item_elem = ET.SubElement(parent, "item")
                self._dict_to_xml(item, item_elem)
        else:
            parent.text = str(data)
    
    def _generate_csv_report(self, report_data, output_file):
        """Generate CSV report"""
        try:
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                
                # Write headers
                writer.writerow(["Type", "Target", "Vulnerability", "Severity", "Description"])
                
                # Extract and write vulnerability data
                results = report_data["results"]
                if isinstance(results, list):
                    for result in results:
                        if isinstance(result, dict) and 'vulnerabilities' in result:
                            target = result.get('target', 'Unknown')
                            for vuln in result['vulnerabilities']:
                                writer.writerow([
                                    vuln.get('type', 'Unknown'),
                                    target,
                                    vuln.get('cve_id', vuln.get('vulnerability', 'N/A')),
                                    vuln.get('severity', 'Unknown'),
                                    vuln.get('description', vuln.get('evidence', 'No description'))
                                ])
            
            logger.info(f"CSV report generated: {output_file}")
            return {"status": "success", "file": str(output_file), "format": "CSV"}
            
        except Exception as e:
            error_msg = f"Failed to generate CSV report: {e}"
            logger.error(error_msg)
            return {"status": "error", "message": error_msg}
    
    def _generate_html_report(self, report_data, output_file):
        """Generate HTML report"""
        try:
            html_content = self._create_html_template(report_data)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"HTML report generated: {output_file}")
            return {"status": "success", "file": str(output_file), "format": "HTML"}
            
        except Exception as e:
            error_msg = f"Failed to generate HTML report: {e}"
            logger.error(error_msg)
            return {"status": "error", "message": error_msg}
    
    def _create_html_template(self, report_data):
        """Create HTML report template"""
        summary = report_data["summary"]
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberNox Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; margin-bottom: 30px; border-bottom: 2px solid #333; padding-bottom: 20px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .summary-card {{ background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; border-left: 4px solid #007bff; }}
        .summary-card h3 {{ margin: 0 0 10px 0; color: #333; }}
        .summary-card .number {{ font-size: 2em; font-weight: bold; color: #007bff; }}
        .critical {{ border-left-color: #dc3545; }}
        .critical .number {{ color: #dc3545; }}
        .high {{ border-left-color: #fd7e14; }}
        .high .number {{ color: #fd7e14; }}
        .medium {{ border-left-color: #ffc107; }}
        .medium .number {{ color: #ffc107; }}
        .low {{ border-left-color: #28a745; }}
        .low .number {{ color: #28a745; }}
        .results {{ margin-top: 30px; }}
        .result-item {{ background: #f8f9fa; margin: 10px 0; padding: 15px; border-radius: 5px; border-left: 4px solid #dee2e6; }}
        .vulnerability {{ margin: 10px 0; padding: 10px; background: white; border-radius: 5px; border: 1px solid #dee2e6; }}
        .vuln-critical {{ border-left: 4px solid #dc3545; }}
        .vuln-high {{ border-left: 4px solid #fd7e14; }}
        .vuln-medium {{ border-left: 4px solid #ffc107; }}
        .vuln-low {{ border-left: 4px solid #28a745; }}
        .metadata {{ background: #e9ecef; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ CyberNox Security Report</h1>
            <p>Generated on {report_data['metadata']['scan_date']}</p>
        </div>
        
        <div class="metadata">
            <h3>Report Metadata</h3>
            <p><strong>Tool:</strong> {report_data['metadata']['tool']} v{report_data['metadata'].get('version', '1.0.0')}</p>
            <p><strong>Report Type:</strong> {report_data['metadata']['report_type']}</p>
            <p><strong>Scan Date:</strong> {report_data['metadata']['scan_date']}</p>
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <h3>Total Vulnerabilities</h3>
                <div class="number">{summary['vulnerabilities_found']}</div>
            </div>
            <div class="summary-card critical">
                <h3>Critical</h3>
                <div class="number">{summary['critical_issues']}</div>
            </div>
            <div class="summary-card high">
                <h3>High</h3>
                <div class="number">{summary['high_issues']}</div>
            </div>
            <div class="summary-card medium">
                <h3>Medium</h3>
                <div class="number">{summary['medium_issues']}</div>
            </div>
            <div class="summary-card low">
                <h3>Low</h3>
                <div class="number">{summary['low_issues']}</div>
            </div>
        </div>
        
        <div class="results">
            <h2>Detailed Results</h2>
            {self._generate_html_results(report_data['results'])}
        </div>
    </div>
</body>
</html>
        """
        return html
    
    def _generate_html_results(self, results):
        """Generate HTML for detailed results"""
        html_results = ""
        
        if isinstance(results, list):
            for i, result in enumerate(results):
                if isinstance(result, dict):
                    target = result.get('target', f'Result {i+1}')
                    html_results += f'<div class="result-item"><h3>Target: {target}</h3>'
                    
                    if 'vulnerabilities' in result:
                        for vuln in result['vulnerabilities']:
                            severity = vuln.get('severity', 'Low').lower()
                            html_results += f'''
                            <div class="vulnerability vuln-{severity}">
                                <h4>{vuln.get('type', 'Unknown Vulnerability')}</h4>
                                <p><strong>Severity:</strong> {vuln.get('severity', 'Unknown')}</p>
                                <p><strong>Description:</strong> {vuln.get('description', vuln.get('evidence', 'No description available'))}</p>
                            </div>
                            '''
                    
                    html_results += '</div>'
        
        return html_results
    
    def _generate_text_report(self, report_data, output_file):
        """Generate plain text report"""
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write("=" * 60 + "\n")
                f.write("CyberNox Security Report\n")
                f.write("=" * 60 + "\n\n")
                
                # Metadata
                f.write("Report Metadata:\n")
                f.write("-" * 20 + "\n")
                for key, value in report_data["metadata"].items():
                    f.write(f"{key.replace('_', ' ').title()}: {value}\n")
                f.write("\n")
                
                # Summary
                f.write("Summary:\n")
                f.write("-" * 20 + "\n")
                for key, value in report_data["summary"].items():
                    f.write(f"{key.replace('_', ' ').title()}: {value}\n")
                f.write("\n")
                
                # Results
                f.write("Detailed Results:\n")
                f.write("-" * 20 + "\n")
                f.write(json.dumps(report_data["results"], indent=2))
            
            logger.info(f"Text report generated: {output_file}")
            return {"status": "success", "file": str(output_file), "format": "TXT"}
            
        except Exception as e:
            error_msg = f"Failed to generate text report: {e}"
            logger.error(error_msg)
            return {"status": "error", "message": error_msg}

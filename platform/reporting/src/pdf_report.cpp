#include "ecdat/reporting.hpp"
#include "ecdat/serialization.hpp"

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace ecdat::reporting {

namespace {

// Sanitize string for PDF literal text: escape (, ), and \.
std::string pdf_escape(const std::string& str) {
    std::string out;
    out.reserve(str.size() + 16);
    for (char c : str) {
        if (c == '(' || c == ')' || c == '\\') {
            out.push_back('\\');
            out.push_back(c);
        } else if (c >= 32 && c <= 126) {
            out.push_back(c);
        } else if (c == '\t') {
            out.append("    ");
        } else {
            out.push_back(' '); // Replace non-printable ASCII with space
        }
    }
    return out;
}

// Simple text wrapper based on approximate character width
std::vector<std::string> wrap_text(const std::string& text, std::size_t max_chars_per_line) {
    std::vector<std::string> lines;
    if (text.empty()) {
        lines.push_back("");
        return lines;
    }

    std::istringstream iss(text);
    std::string word;
    std::string current_line;

    while (iss >> word) {
        if (current_line.empty()) {
            current_line = word;
        } else if (current_line.size() + 1 + word.size() <= max_chars_per_line) {
            current_line += " " + word;
        } else {
            lines.push_back(current_line);
            current_line = word;
        }
    }
    if (!current_line.empty()) {
        lines.push_back(current_line);
    }
    return lines;
}

// Minimalist native PDF 1.4 multi-page document builder
class PdfBuilder {
public:
    PdfBuilder() = default;

    void add_page() {
        if (!current_stream_.empty()) {
            page_streams_.push_back(current_stream_);
            current_stream_.clear();
        }
        current_y_ = kPageHeight - kMarginTop;
        page_num_++;
    }

    void draw_rect(double x, double y, double w, double h, double r, double g, double b, bool fill = true) {
        std::ostringstream ss;
        ss << std::fixed << std::setprecision(2);
        ss << r << " " << g << " " << b << (fill ? " rg\n" : " RG\n");
        ss << x << " " << y << " " << w << " " << h << " re " << (fill ? "f\n" : "S\n");
        current_stream_ += ss.str();
    }

    void draw_line(double x1, double y1, double x2, double y2, double r, double g, double b, double width = 1.0) {
        std::ostringstream ss;
        ss << std::fixed << std::setprecision(2);
        ss << width << " w\n";
        ss << r << " " << g << " " << b << " RG\n";
        ss << x1 << " " << y1 << " m " << x2 << " " << y2 << " l S\n";
        current_stream_ += ss.str();
    }

    void draw_text(double x, double y, const std::string& text, const std::string& font, double size, double r = 0, double g = 0, double b = 0) {
        std::ostringstream ss;
        ss << std::fixed << std::setprecision(2);
        ss << "BT\n";
        ss << "/" << font << " " << size << " Tf\n";
        ss << r << " " << g << " " << b << " rg\n";
        ss << x << " " << y << " Td\n";
        ss << "(" << pdf_escape(text) << ") Tj\n";
        ss << "ET\n";
        current_stream_ += ss.str();
    }

    double current_y() const { return current_y_; }
    void set_y(double y) { current_y_ = y; }
    void advance_y(double delta) { current_y_ -= delta; }

    void ensure_space(double required_height, const std::string& target_path, const std::string& timestamp) {
        if (current_y_ - required_height < kMarginBottom) {
            draw_footer();
            add_page();
            draw_header(target_path, timestamp);
        }
    }

    void draw_header(const std::string& target_path, const std::string& timestamp) {
        // Banner background
        draw_rect(kMarginLeft, current_y_ - 30, kPrintWidth, 34, 0.08, 0.18, 0.36, true);
        // Header text
        draw_text(kMarginLeft + 12, current_y_ - 18, "ECDAT — Cryptographic Assessment Report", "F2", 14, 1.0, 1.0, 1.0);
        draw_text(kMarginLeft + 12, current_y_ - 27, "Target: " + target_path + "   |   Generated: " + timestamp, "F1", 8, 0.85, 0.90, 1.0);
        advance_y(44);
    }

    void draw_footer() {
        draw_line(kMarginLeft, kMarginBottom + 12, kMarginLeft + kPrintWidth, kMarginBottom + 12, 0.8, 0.8, 0.8, 0.5);
        draw_text(kMarginLeft, kMarginBottom + 2, "ECDAT v" ECDAT_VERSION " • Enterprise Cryptography Discovery & Assessment Tool • Native C++20", "F1", 7, 0.45, 0.45, 0.45);
        std::string ptxt = "Page " + std::to_string(page_num_);
        draw_text(kMarginLeft + kPrintWidth - 40, kMarginBottom + 2, ptxt, "F1", 7, 0.45, 0.45, 0.45);
    }

    std::string build_pdf() {
        if (!current_stream_.empty()) {
            draw_footer();
            page_streams_.push_back(current_stream_);
            current_stream_.clear();
        }

        std::size_t total_pages = page_streams_.empty() ? 1 : page_streams_.size();
        if (page_streams_.empty()) {
            page_streams_.push_back("");
        }

        std::ostringstream out;
        std::vector<std::size_t> xref_offsets;

        out << "%PDF-1.4\n%\xe2\xe3\xcf\xd3\n";

        // Object 1: Catalog
        xref_offsets.push_back(out.tellp());
        out << "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n";

        // Object 2: Pages Root
        xref_offsets.push_back(out.tellp());
        out << "2 0 obj\n<< /Type /Pages /Kids [";
        for (std::size_t i = 0; i < total_pages; ++i) {
            out << (3 + i * 2) << " 0 R ";
        }
        out << "] /Count " << total_pages << " >>\nendobj\n";

        // Font Objects: F1 (Helvetica), F2 (Helvetica-Bold)
        std::size_t f1_obj = 3 + total_pages * 2;
        std::size_t f2_obj = f1_obj + 1;

        // Pages & Content Streams
        for (std::size_t i = 0; i < total_pages; ++i) {
            std::size_t page_obj = 3 + i * 2;
            std::size_t content_obj = page_obj + 1;

            // Page Dict
            xref_offsets.push_back(out.tellp());
            out << page_obj << " 0 obj\n"
                << "<< /Type /Page /Parent 2 0 R\n"
                << "   /MediaBox [0 0 " << kPageWidth << " " << kPageHeight << "]\n"
                << "   /Contents " << content_obj << " 0 R\n"
                << "   /Resources << /Font << /F1 " << f1_obj << " 0 R /F2 " << f2_obj << " 0 R >> >>\n"
                << ">>\nendobj\n";

            // Content Stream
            const std::string& stream_data = page_streams_[i];
            xref_offsets.push_back(out.tellp());
            out << content_obj << " 0 obj\n"
                << "<< /Length " << stream_data.size() << " >>\nstream\n"
                << stream_data
                << "\nendstream\nendobj\n";
        }

        // Font F1 (Helvetica Regular)
        xref_offsets.push_back(out.tellp());
        out << f1_obj << " 0 obj\n"
            << "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>\nendobj\n";

        // Font F2 (Helvetica Bold)
        xref_offsets.push_back(out.tellp());
        out << f2_obj << " 0 obj\n"
            << "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>\nendobj\n";

        // Cross-Reference Table
        std::size_t xref_start = out.tellp();
        std::size_t total_objects = xref_offsets.size() + 1;

        out << "xref\n0 " << total_objects << "\n";
        out << "0000000000 65535 f \n";
        for (std::size_t offset : xref_offsets) {
            out << std::setfill('0') << std::setw(10) << offset << " 00000 n \n";
        }

        // Trailer
        out << "trailer\n"
            << "<< /Size " << total_objects << " /Root 1 0 R >>\n"
            << "startxref\n"
            << xref_start << "\n"
            << "%%EOF\n";

        return out.str();
    }

private:
    static constexpr double kPageWidth = 612.0;   // Standard Letter
    static constexpr double kPageHeight = 792.0;
    static constexpr double kMarginLeft = 40.0;
    static constexpr double kMarginTop = 40.0;
    static constexpr double kMarginBottom = 40.0;
    static constexpr double kPrintWidth = kPageWidth - (kMarginLeft * 2);

    double current_y_ = kPageHeight - kMarginTop;
    std::size_t page_num_ = 0;
    std::string current_stream_;
    std::vector<std::string> page_streams_;
};

} // namespace

std::string generate_pdf(const storage::ScanDetail& detail) {
    PdfBuilder pdf;
    pdf.add_page();

    const std::string target = detail.scan.target_path.empty() ? "(unspecified)" : detail.scan.target_path;
    const std::string timestamp = detail.scan.timestamp.empty() ? storage::Storage::current_timestamp() : detail.scan.timestamp;

    // First page top banner
    pdf.draw_header(target, timestamp);

    // ============================================================
    // 1. Executive Summary Box
    // ============================================================
    pdf.draw_rect(40, pdf.current_y() - 85, 532, 85, 0.96, 0.97, 0.98, true);
    pdf.draw_rect(40, pdf.current_y() - 85, 532, 85, 0.80, 0.84, 0.88, false);

    pdf.draw_text(52, pdf.current_y() - 16, "EXECUTIVE SUMMARY & INVENTORY METRICS", "F2", 10, 0.1, 0.2, 0.35);

    // Statistics Columns
    pdf.draw_text(52, pdf.current_y() - 34, "Total Assets Discovered:", "F1", 9, 0.2, 0.2, 0.2);
    pdf.draw_text(180, pdf.current_y() - 34, std::to_string(detail.scan.total_assets), "F2", 9, 0.0, 0.0, 0.0);

    pdf.draw_text(52, pdf.current_y() - 48, "Algorithm Status Breakdown:", "F1", 9, 0.2, 0.2, 0.2);
    std::string status_summary = "Safe: " + std::to_string(detail.scan.safe_count) +
                                 "  |  Weak: " + std::to_string(detail.scan.weak_count) +
                                 "  |  Deprecated: " + std::to_string(detail.scan.deprecated_count) +
                                 "  |  Unknown: " + std::to_string(detail.scan.unknown_count);
    pdf.draw_text(180, pdf.current_y() - 48, status_summary, "F2", 9, 0.1, 0.3, 0.1);

    pdf.draw_text(52, pdf.current_y() - 62, "Risk Tier Distribution:", "F1", 9, 0.2, 0.2, 0.2);
    std::string risk_summary = "Critical: " + std::to_string(detail.scan.critical_risk_count) +
                               "  |  High: " + std::to_string(detail.scan.high_risk_count) +
                               "  |  Medium: " + std::to_string(detail.scan.medium_risk_count) +
                               "  |  Low: " + std::to_string(detail.scan.low_risk_count);
    pdf.draw_text(180, pdf.current_y() - 62, risk_summary, "F2", 9, 0.8, 0.1, 0.1);

    // PQC Readiness indicator
    std::ostringstream pss;
    pss << std::fixed << std::setprecision(1) << detail.scan.pqc_readiness_pct;
    std::string pqc_str = "PQC Readiness Score: " + pss.str() + "% (" +
                          std::to_string(detail.scan.pqc_ready_count) + " / " +
                          std::to_string(detail.scan.total_assets) + " assets ready)";
    pdf.draw_text(52, pdf.current_y() - 76, pqc_str, "F2", 9, 0.0, 0.4, 0.6);

    pdf.advance_y(100);

    // ============================================================
    // 2. Findings Section Header
    // ============================================================
    pdf.draw_text(40, pdf.current_y(), "DETAILED CRYPTOGRAPHIC FINDINGS", "F2", 11, 0.1, 0.2, 0.35);
    pdf.draw_line(40, pdf.current_y() - 4, 572, pdf.current_y() - 4, 0.1, 0.2, 0.35, 1.0);
    pdf.advance_y(16);

    if (detail.findings.empty()) {
        pdf.draw_rect(40, pdf.current_y() - 36, 532, 36, 0.95, 0.98, 0.95, true);
        pdf.draw_text(52, pdf.current_y() - 22, "No cryptographic findings or security issues detected for this target.", "F1", 9, 0.1, 0.5, 0.1);
        pdf.advance_y(46);
    } else {
        for (std::size_t i = 0; i < detail.findings.size(); ++i) {
            const auto& f = detail.findings[i];

            // Calculate card height dynamically
            auto why_lines = wrap_text(f.why.empty() ? "None reported" : f.why, 85);
            auto act_lines = wrap_text(f.action.empty() ? "No action required" : f.action, 85);
            double card_height = 58.0 + (why_lines.size() + act_lines.size()) * 11.0;

            pdf.ensure_space(card_height + 12, target, timestamp);

            // Card background & border
            double cy = pdf.current_y();
            pdf.draw_rect(40, cy - card_height, 532, card_height, 0.98, 0.98, 0.99, true);
            pdf.draw_rect(40, cy - card_height, 532, card_height, 0.85, 0.87, 0.90, false);

            // Severity colored side bar
            if (f.risk_level == "CRITICAL") {
                pdf.draw_rect(40, cy - card_height, 4, card_height, 0.85, 0.1, 0.1, true);
            } else if (f.risk_level == "HIGH") {
                pdf.draw_rect(40, cy - card_height, 4, card_height, 0.90, 0.4, 0.0, true);
            } else if (f.risk_level == "MEDIUM") {
                pdf.draw_rect(40, cy - card_height, 4, card_height, 0.85, 0.7, 0.1, true);
            } else {
                pdf.draw_rect(40, cy - card_height, 4, card_height, 0.15, 0.65, 0.25, true);
            }

            // Finding Title Line
            std::string title = "[" + std::to_string(i + 1) + "] " + f.algorithm;
            if (f.key_size > 0) title += " (" + std::to_string(f.key_size) + "-bit)";
            if (!f.curve.empty()) title += " [" + f.curve + "]";
            title += "  —  Status: " + std::string(status_to_string(f.status));
            title += "  |  Risk: " + std::to_string(static_cast<int>(f.risk_score + 0.5)) + " (" + f.risk_level + ")";
            title += "  |  PQC: " + std::string(f.pqc_flag ? "YES" : "NO");

            pdf.draw_text(50, cy - 14, title, "F2", 9, 0.1, 0.1, 0.2);

            // Location
            std::string loc = "Where:  " + (f.where_text.empty() ? f.file : f.where_text);
            pdf.draw_text(50, cy - 26, loc, "F1", 8, 0.3, 0.3, 0.3);

            // Why Lines
            double cur_line_y = cy - 38;
            pdf.draw_text(50, cur_line_y, "Why:", "F2", 8, 0.3, 0.3, 0.3);
            for (std::size_t l = 0; l < why_lines.size(); ++l) {
                pdf.draw_text(85, cur_line_y, why_lines[l], "F1", 8, 0.2, 0.2, 0.2);
                cur_line_y -= 11.0;
            }

            // Action Lines
            pdf.draw_text(50, cur_line_y, "Action:", "F2", 8, 0.1, 0.4, 0.7);
            for (std::size_t l = 0; l < act_lines.size(); ++l) {
                pdf.draw_text(85, cur_line_y, act_lines[l], "F2", 8, 0.1, 0.35, 0.65);
                cur_line_y -= 11.0;
            }

            pdf.advance_y(card_height + 8.0);
        }
    }

    return pdf.build_pdf();
}

bool write_pdf(const storage::ScanDetail& detail, const std::string& filepath) {
    try {
        std::filesystem::path p(filepath);
        if (p.has_parent_path()) {
            std::filesystem::create_directories(p.parent_path());
        }
        std::ofstream out(filepath, std::ios::binary);
        if (!out.is_open()) return false;
        std::string pdf_data = generate_pdf(detail);
        out.write(pdf_data.data(), pdf_data.size());
        return out.good();
    } catch (...) {
        return false;
    }
}

} // namespace ecdat::reporting

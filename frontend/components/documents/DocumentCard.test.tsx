import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { DocumentCard, type DocumentStatus } from "./DocumentCard";

/**
 * The document card, and the things it must never leak.
 *
 * A stored document's location is not disclosed to a caller by design, so the
 * card has no prop that could carry a bucket, an object key, a tenant path, or
 * the encrypted filename. These tests pin that shape.
 */

const STORED: DocumentStatus = {
  name: "ConsultingInvoice.docx",
  status: "stored",
  byteSize: 141,
  detected: 16,
};

describe("status", () => {
  it("checks every stage once the backend reports stored", () => {
    render(<DocumentCard document={STORED} />);
    const card = screen.getByTestId("document-card");

    for (const label of ["Uploaded", "Encrypted", "Stored"]) {
      expect(card.textContent).toContain(label);
    }
    // Status is conveyed in text as well as colour and glyph.
    expect(card.querySelectorAll(".sr-only").length).toBeGreaterThan(0);
  });

  it("does not assert stored for a status the backend has not reported", () => {
    render(<DocumentCard document={{ ...STORED, status: "received" }} />);

    const checks = screen.getByTestId("document-card").querySelectorAll("li");
    const stored = Array.from(checks).find((li) => li.textContent?.includes("Stored"));
    expect(stored?.textContent).toContain("not started");
  });

  it("shows the detected count only once processing produced one", () => {
    render(<DocumentCard document={{ ...STORED, detected: null }} />);

    expect(screen.queryByText("Detected")).toBeNull();
  });

  it("reports the real detected count when present", () => {
    render(<DocumentCard document={STORED} />);

    expect(screen.getByText("16 entities")).toBeTruthy();
  });
});

describe("disclosure limits", () => {
  it("shows the caller's filename and no storage location", () => {
    render(<DocumentCard document={STORED} />);
    const text = screen.getByTestId("document-card").textContent ?? "";

    expect(text).toContain("ConsultingInvoice.docx");
    // None of these are props on DocumentStatus, and must never become props.
    expect(text).not.toMatch(/unique-app-storage|s3:\/\/|arn:aws|tenants?\//i);
    expect(text).not.toMatch(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}/); // no object id
  });

  it("describes storage without naming a bucket", () => {
    render(<DocumentCard document={STORED} />);

    expect(screen.getByText("AWS S3 (private)")).toBeTruthy();
  });
});

describe("layout", () => {
  it("truncates a long filename rather than widening the card", () => {
    render(<DocumentCard document={{ ...STORED, name: `${"long".repeat(40)}.docx` }} />);

    expect(screen.getByRole("heading", { level: 3 }).className).toContain("truncate");
  });
});

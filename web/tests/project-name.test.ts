import { describe, expect, it } from "vitest";
import { projectHost, projectName } from "../lib/format";

describe("project names", () => {
  it("names a repository on a code host owner/repo", () => {
    expect(projectName("https://github.com/acme/payments-api")).toBe("acme/payments-api");
    expect(projectName("github.com/juice-shop/juice-shop")).toBe("juice-shop/juice-shop");
    expect(projectName("https://gitlab.com/group/sub/repo.git")).toBe("group/sub/repo");
    expect(projectName("https://www.bitbucket.org/team/app/")).toBe("team/app");
    expect(projectHost("https://github.com/acme/payments-api")).toBe("github.com");
  });

  it("names a web target by its host and path", () => {
    expect(projectName("https://shop.example.com")).toBe("shop.example.com");
    expect(projectName("https://shop.example.com:8443/api/")).toBe("shop.example.com:8443/api");
    expect(projectHost("https://shop.example.com")).toBeNull();
  });

  it("leaves uploads, imports and a bare host page alone", () => {
    for (const label of ["CycloneDX: sbom.cdx.json", "archive.zip", "my project", "https://github.com/acme", ""]) {
      expect(projectHost(label)).toBeNull();
    }
    expect(projectName("CycloneDX: sbom.cdx.json")).toBe("CycloneDX: sbom.cdx.json");
    expect(projectName("archive.zip")).toBe("archive.zip");
    expect(projectName("my project")).toBe("my project");
    expect(projectName("https://github.com/acme")).toBe("github.com/acme");
  });
});

/*
 * Copyright (c) 2024 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import Foundation
import Testing
import RQESLib
import CryptoKit
@testable import RqesKit

@Suite("DocumentRetrievalService")
struct DocumentRetrievalServiceTests {

    @Test func documentRetrievalTest() async throws {
        
        let url = "https://dev.recruitment.demo.eudiw.dev?request_uri=https://dev.recruitment.demo.eudiw.dev/api/request.jwt/a35055cd-1cbf-4c50-b384-d1b39dea5404&client_id=dev.recruitment.demo.eudiw.dev"
        
        let cacheDir = try! makeTempDir()

        try FileManager.default.createDirectory(
            at: cacheDir,
            withIntermediateDirectories: true
        )
        
        let documentRetrieval: DocumentRetrieving = DocumentRetrieval(
            config: .init(
                issuer: nil,
                supportedClientIdSchemes: [.x509SanDns(trust: { _ in true })]
            )
        )
        
        let service = try DocumentRetrievalService(
            client: documentRetrieval,
        )
        
        let result = try await service.resolveDocument(requestUri: .init(string: url)!)
        
        switch result {
        case .success(let outcome):
            print(outcome)
            
            _ = try await outcome.dispatch(signedDocuments: [])
        case .failure: break
        }
    }
    
    @Test("Happy path: downloads, validates base64 hash, writes to downloadTempDir, returns success")
    func happyPath() async throws {
        installURLProtocolStub()
        defer { uninstallURLProtocolStub() }

        let remote1 = URL(string: "https://example.com/doc1")!
        let remote2 = URL(string: "https://example.com/doc2")!

        let data1 = "signed-1".data(using: .utf8)!
        let data2 = "signed-2".data(using: .utf8)!
        
        let locations = [
            DocumentLocation(uri: remote1.absoluteString, method: .init(type: "")),
            DocumentLocation(uri: remote2.absoluteString, method: .init(type: ""))
        ]
        
        let digests = [
            DocumentDigest(label: "doc1.bin", hash: try! DocumentRetrievalService.hashBase64(of: data1, algorithm: .SHA256)),
            DocumentDigest(label: "doc2.bin", hash: try! DocumentRetrievalService.hashBase64(of: data2, algorithm: .SHA256))
        ]
        
        let client = MockDocumentRetrieving(
            documents: locations,
            digests: digests
        )
        let sut = try DocumentRetrievalService(client: client)

        StubURLProtocol.setStub(.init(statusCode: 200, data: data1, error: nil), for: remote1)
        StubURLProtocol.setStub(.init(statusCode: 200, data: data2, error: nil), for: remote2)

        let result = try await sut.resolveDocument(requestUri: URL(string: "https://example.com/request")!)

        switch result {
        case .success(let anyOutcome):
            let outcome = anyOutcome as? ResolutionOutcome
            #expect(outcome != nil)

            #expect(outcome?.resolvedDocuments.count == 2)

        case .failure(let error):
            Issue.record("Expected success, got failure: \(error)")
        }
    }

    @Test("Hash mismatch throws ValidationError.hashMismatch")
    func hashMismatchThrows() async throws {
        installURLProtocolStub()
        defer { uninstallURLProtocolStub() }

        let tempDir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let client = MockDocumentRetrieving()
        let sut = try DocumentRetrievalService(client: client)

        let remote = URL(string: "https://example.com/doc")!
        let data = "actual".data(using: .utf8)!
        
        StubURLProtocol.setStub(.init(statusCode: 200, data: data, error: nil), for: remote)

        do {
            _ = try await sut.resolveDocument(requestUri: URL(string: "https://example.com/request")!)
            Issue.record("Expected hashMismatch to be thrown")
        } catch let e as ValidationError {
            #expect({
                if case .hashMismatch = e { return true }
                return false
            }())
        }
    }

    @Test("Unsupported hash algorithm throws validationError")
    func unsupportedAlgorithmThrows() async throws {
        installURLProtocolStub()
        defer { uninstallURLProtocolStub() }

        let tempDir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let client = MockDocumentRetrieving(hash: "wrong")
        let sut = try DocumentRetrievalService(client: client)

        let remote = URL(string: "https://example.com/doc")!
        let data = Data([0x01, 0x02, 0x03])
        StubURLProtocol.setStub(.init(statusCode: 200, data: data, error: nil), for: remote)

        do {
            _ = try await sut.resolveDocument(requestUri: URL(string: "https://example.com/request")!)
            Issue.record("Expected unsupported algorithm error to be thrown")
        } catch let e as ValidationError {
            #expect({
                if case .validationError(let msg) = e {
                    return msg.contains("Unsupported hash algorith")
                }
                return false
            }())
        }
    }

    @Test("Missing resolved fields throws validationError")
    func missingResolvedFieldsThrows() async throws {
        let tempDir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let client = MockDocumentRetrieving(documents: nil)
        let sut = try DocumentRetrievalService(client: client)

        do {
            _ = try await sut.resolveDocument(requestUri: URL(string: "https://example.com/request")!)
            Issue.record("Expected validationError to be thrown")
        } catch let e as ValidationError {
            #expect({
                if case .validationError(let msg) = e {
                    return msg.contains("Unable to resolve request")
                }
                return false
            }())
        }
    }
}

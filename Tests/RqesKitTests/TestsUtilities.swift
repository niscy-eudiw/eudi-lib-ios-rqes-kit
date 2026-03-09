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
import RQESLib
import CryptoKit
@testable import RqesKit

final class StubURLProtocol: URLProtocol {
    struct Stub {
        let statusCode: Int
        let data: Data
        let error: Error?
    }

    nonisolated(unsafe) static var stubs: [String: Stub] = [:]
    private static let lock = NSLock()

    
    static func setStub(_ stub: Stub, for url: URL) {
        lock.lock(); defer { lock.unlock() }
        stubs[url.absoluteString] = stub
    }

    static func removeAllStubs() {
        lock.lock(); defer { lock.unlock() }
        stubs.removeAll()
    }

    private static func stub(for url: URL) -> Stub? {
        lock.lock(); defer { lock.unlock() }
        return stubs[url.absoluteString]
    }
    
    override class func canInit(with request: URLRequest) -> Bool {
        guard let url = request.url else { return false }
        return Self.hasStub(for: url)   // only intercept when stub is present
    }
    
    private static func hasStub(for url: URL) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return stubs[url.absoluteString] != nil
    }
    
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let url = request.url else {
            client?.urlProtocol(self, didFailWithError: URLError(.badURL))
            return
        }

        guard let stub = Self.stub(for: url) else {
            client?.urlProtocol(self, didFailWithError: URLError(.resourceUnavailable))
            return
        }

        if let error = stub.error {
            client?.urlProtocol(self, didFailWithError: error)
            return
        }

        let response = HTTPURLResponse(
            url: url,
            statusCode: stub.statusCode,
            httpVersion: "HTTP/1.1",
            headerFields: nil
        )!

        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: stub.data)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

internal func installURLProtocolStub() {
    URLProtocol.registerClass(StubURLProtocol.self)
}

internal func uninstallURLProtocolStub() {
    URLProtocol.unregisterClass(StubURLProtocol.self)
    StubURLProtocol.stubs = [:]
}

internal func makeTempDir() throws -> URL {
    let dir = FileManager.default.temporaryDirectory
        .appendingPathComponent("DocumentRetrievalServiceTests-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    return dir
}

final class MockDocumentRetrieving: DocumentRetrieving {
    
    let hash: String
    let documents: [DocumentLocation]?
    let digests: [DocumentDigest]?
    
    init(
        hash: String = "2.16.840.1.101.3.4.2.1",
        documents: [DocumentLocation]? = [DocumentLocation(uri: "https://example.com/doc", method: .init(type: "type"))],
        digests: [DocumentDigest]? = [DocumentDigest(label: "kabel", hash: "hash")]
    ) {
        self.hash = hash
        self.documents = documents
        self.digests = digests
    }
    
    func resolve(documentRetrievalConfiguration: RQESLib.DocumentRetrievalConfiguration, unvalidatedRequest: RQESLib.UnvalidatedRequest) async throws -> RQESLib.AuthorizationRequest {
        try await resolveResult()
    }
    
    func dispatch(poster: any RQESLib.Posting, reslovedData: RQESLib.ResolvedRequestData, consent: RQESLib.Consent) async throws -> RQESLib.DispatchOutcome {
        throw ValidationError.validationError("Not implemented")
    }
    
    let config = DocumentRetrievalConfiguration(
        issuer: nil,
        supportedClientIdSchemes: []
    )
    
    let parseResult: Result<UnvalidatedRequest, Error> = .success(
        .plain(.init(
            responseType: nil,
            clientId: nil,
            clientIdScheme: nil,
            responseMode: nil,
            responseUri: nil,
            requestUri: nil,
            nonce: nil,
            state: nil,
            signatureQualifier: nil,
            documentDigests: nil,
            documentLocations: nil,
            hashAlgorithmOID: nil,
            clientData: nil)
        )
    )
    func resolveResult() async throws -> AuthorizationRequest {
        await .jwt(request: try .init(
        config: .init(issuer: nil, supportedClientIdSchemes: []),
        validatedAuthorizationRequest: ValidatedRequestData(
            request: .init(
                clientId: "",
                client: .preRegistered(clientId: "", legalName: ""),
                nonce: "", responseUri: "https://www.example.com",
                responseMode: nil,
                state: nil,
                signatureQualifier: nil,
                documentDigests: self.digests,
                documentLocations: self.documents,
                hashAlgorithmOID: self.hash,
                clientData: nil
            )
        )))
    }

    func parse(url: URL) async throws -> Result<RQESLib.UnvalidatedRequest, any Error> { parseResult }
}

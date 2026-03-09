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
@_exported import RQESLib

public protocol DocumentRetrievalServiceType: Sendable {
    
    var downloadTempDir: URL { get }
    var client: DocumentRetrieving { get }
    
    /// Retrieves the documents from the given URI.
    /// - Parameter requestUri: The URI of the document to be retrieved.
    /// - Returns: The outcome of the resolution.
    func resolveDocument(
        requestUri: URL
    ) async throws -> Result<ResolutionOutcomeType, Error>
}

public final class DocumentRetrievalService: DocumentRetrievalServiceType {
    
    public let downloadTempDir: URL
    public let client: DocumentRetrieving
    
    public init(
        client: DocumentRetrieving
    ) throws {
      self.downloadTempDir = try Self.makeTempDir()
        self.client = client
    }
    
    private static func makeTempDir() throws -> URL {
        let cacheDir = FileManager
        .default
        .temporaryDirectory
        .appendingPathComponent((UUID().uuidString), isDirectory: true)
      
        try FileManager.default.createDirectory(
          at: cacheDir,
          withIntermediateDirectories: true
        )
      
        return cacheDir
    }
  
    public func resolveDocument(requestUri: URL) async throws -> Result<ResolutionOutcomeType, any Error> {
        let result = try await client.parse(url: requestUri)
        switch result {
        case .success(let request):
            let request = try await client.resolve(
                documentRetrievalConfiguration: client.config,
                unvalidatedRequest: request
            )
            
            guard
                let resolved = request.resolved,
                let documentLocations = resolved.documentLocations,
                let documentDigests = resolved.documentDigests,
                let hashAlgorithm = resolved.hashAlgorithmOID
            else {
                throw ValidationError.validationError("Unable to resolve request")
            }
            
            let pairs = Array(
                zip(documentLocations, documentDigests)
            )
            
            let resolvedDocumentUrls = try await downloadAndStoreDocuments(
                pairs: pairs,
                algorithm: .init(hashAlgorithm)
            )
            
            let resolvedDocuments: [ResolvedDocument] = resolvedDocumentUrls.map { result in
                .init(
                    location: result.location,
                    digest: result.digest,
                    file: result.localURL
                )
            }
            
            return .success(ResolutionOutcome.make(
                resolvedDocuments: resolvedDocuments,
                requestObject: resolved,
                client: client
            ))
            
        case .failure(let error):
            throw error
        }
    }
    
    private func downloadAndStoreDocuments(
        pairs: [(DocumentLocation, DocumentDigest)],
        algorithm oid: HashAlgorithmOID
    ) async throws -> [(localURL: URL, location: DocumentLocation, digest: DocumentDigest)] {

        let cacheDir = downloadTempDir

        // Ensure the validator used inside tasks is @Sendable
        let validate: @Sendable (Data, DocumentDigest, HashAlgorithmOID) throws -> Void = Self.defaultSHA256Validator

        return try await withThrowingTaskGroup(
            of: (localURL: URL, location: DocumentLocation, digest: DocumentDigest).self
        ) { group in

            for (documentLocation, documentDigest) in pairs {
                group.addTask {
                    guard let remoteURL = URL(string: documentLocation.uri) else {
                        throw URLError(.badURL)
                    }

                    // Download as Data
                    let (data, _) = try await URLSession.shared.data(from: remoteURL)

                    try validate(data, documentDigest, oid)

                    // Build local file URL using digest as filename
                    let fileURL = cacheDir.appendingPathComponent(documentDigest.label)

                    // Save to disk (overwrite if exists)
                    try data.write(to: fileURL, options: .atomic)

                    return (
                        localURL: fileURL,
                        location: documentLocation,
                        digest: documentDigest
                    )
                }
            }

            var results: [(localURL: URL, location: DocumentLocation, digest: DocumentDigest)] = []
            for try await value in group { results.append(value) }
            return results
        }
    }
    
    internal static func hashBase64(
        of data: Data,
        algorithm oid: HashAlgorithmOID
    ) throws -> String {

        switch oid {
        case .SHA256:
            return Data(SHA256.hash(data: data)).base64EncodedString()
        case .SHA385:
            return Data(SHA384.hash(data: data)).base64EncodedString()
        case .SHA512:
            return Data(SHA512.hash(data: data)).base64EncodedString()
        default:
            throw ValidationError.validationError("Unsupported hash algorith: \(oid.rawValue)")
        }
    }
    
    private static func defaultSHA256Validator(
        data: Data,
        digest: DocumentDigest,
        algorithm: HashAlgorithmOID
    ) throws {
        let computed = try Self.hashBase64(of: data, algorithm: algorithm)
        guard computed == digest.hash else {
            throw ValidationError.hashMismatch(
                expected: digest.hash,
                actual: computed
            )
        }
    }
}

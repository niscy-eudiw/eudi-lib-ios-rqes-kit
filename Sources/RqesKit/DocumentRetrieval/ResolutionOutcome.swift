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

public enum DocumentDecodeError: Error {
    case unreadableData(URL, underlying: Error)
    case invalidStringEncoding(URL)
}

public protocol ResolutionOutcomeType: Sendable {
    
    var resolvedDocuments: [ResolvedDocument] { get }
    var requestObject: ResolvedRequestData { get }
    var client: DocumentRetrieving { get }
    func dispatch(signedDocuments: [Document]) async throws -> DispatchOutcome
    
    static func make(
        resolvedDocuments: [ResolvedDocument],
        requestObject: ResolvedRequestData,
        client: DocumentRetrieving
    ) -> Self
}

public struct ResolutionOutcome: ResolutionOutcomeType {
    
    public let resolvedDocuments: [ResolvedDocument]
    public let requestObject: ResolvedRequestData
    public let client: DocumentRetrieving

    public init(
        resolvedDocuments: [ResolvedDocument],
        requestObject: ResolvedRequestData,
        client: DocumentRetrieving
    ) {
        self.resolvedDocuments = resolvedDocuments
        self.requestObject = requestObject
        self.client = client
    }
    
    public static func make(
        resolvedDocuments: [ResolvedDocument],
        requestObject: ResolvedRequestData,
        client: DocumentRetrieving
    ) -> Self {
        .init(resolvedDocuments: resolvedDocuments, requestObject: requestObject, client: client)
    }
    
    @discardableResult
    public func dispatch(signedDocuments: [Document]) async throws -> DispatchOutcome {
        return try await client.dispatch(
            poster: Poster(),
            reslovedData: requestObject,
            consent: .positive(
                documentWithSignature: signedDocuments.map { $0.fileURL.absoluteString },
                signatureObject: nil
            )
        )
    }
    
    private func fileToStringStreaming(url: URL, encoding: String.Encoding = .utf8) throws -> String {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }

        var buffer = Data()
        while true {
            let chunk = try handle.read(upToCount: 64 * 1024) ?? Data()
            if chunk.isEmpty { break }
            buffer.append(chunk)
        }

        guard let text = String(data: buffer, encoding: encoding) else {
            throw DocumentDecodeError.invalidStringEncoding(url)
        }
        return text
    }

    func mapDocumentsToStringsStreaming(_ signedDocuments: [Document]) throws -> [String] {
        try signedDocuments.map { try fileToStringStreaming(url: $0.fileURL) }
    }
}

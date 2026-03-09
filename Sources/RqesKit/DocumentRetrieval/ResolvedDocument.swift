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

public struct ResolvedDocument: Sendable {
    public let location: DocumentLocation
    public let digest: DocumentDigest
    public let file: URL
    
    public init(
        location: DocumentLocation,
        digest: DocumentDigest,
        file: URL
    ) {
        self.location = location
        self.digest = digest
        self.file = file
    }
}


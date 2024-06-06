import Foundation
import MdocSecurity18013
import MdocDataModel18013

public struct MDocPresentationState {
    
    public var docs: [String: IssuerSigned]
    public var iaca: [SecCertificate]
    public var dauthMethod: DeviceAuthMethod
    public var devicePrivateKeys: [String: CoseKeyPrivate]
    
    public init(input: MDocInputData, trustedCertificates: [Data], deviceAuthMethod: DeviceAuthMethod) {
        self.iaca = trustedCertificates.compactMap { SecCertificateCreateWithData(nil, $0 as CFData) }
        self.dauthMethod = deviceAuthMethod
        
        switch input {
        case .jsonDocument(let d):
            let sampleData = d.compactMap { $0.decodeJSON(type: SignUpResponse.self) }
            let randomIds = (0..<d.count).map { _ in UUID().uuidString }
            self.docs = Dictionary(uniqueKeysWithValues: sampleData.compactMap { $0.deviceResponse?.documents?.map(\.issuerSigned).first }.enumerated().map { (randomIds[$0], $1) })
            self.devicePrivateKeys = Dictionary(uniqueKeysWithValues: sampleData.compactMap { $0.devicePrivateKey }.enumerated().map { (randomIds[$0], $1) })
        case .documentSignupIssuerSignedObj(let parameters, let devicePrivateKeyObj):
            self.docs = parameters
            self.devicePrivateKeys = devicePrivateKeyObj
        case .documentSignupIssuerSignedData(let data, let devicePrivateKeyData):
            self.docs = data.compactMapValues({ IssuerSigned(data: [UInt8]($0))})
            self.devicePrivateKeys = devicePrivateKeyData.mapValues { CoseKeyPrivate(privateKeyx963Data: $0, crv: .p256) }
        }
    }
}

public enum MDocInputData {
    case jsonDocument(data: [Data])
    case documentSignupIssuerSignedObj(parameters: [String: IssuerSigned], devicePrivateKeyObj: [String: CoseKeyPrivate])
    case documentSignupIssuerSignedData(data: [String: Data], devicePrivateKeyData: [String: Data])
}

//
//  SecStorage.swift
//
//
//  Created by Dmitriy Zharov on 16.01.2024.
//

import SwiftUI
import Security

struct SomeView: View {
    @SecStorage("OpenAI")
    private var accessToken: Data?
    
    var body: some View {
        ZStack {
            Text(accessToken?.description ?? "")
        }
    }
}

import SwiftData

@propertyWrapper public struct SecStorage<Value>: DynamicProperty where Value: GenericPasswordConvertible {
    private let query: SecItemQuery<GenericPassword>
    private let store: GenericPasswordStore
    
    public var wrappedValue: Value? {
        get {
            do {
                return try store.retrieve(query)
            } catch {
                assertionFailure(error.localizedDescription)
                return nil
            }
        }
        nonmutating set {
            do {
                if let newValue {
                    try store.store(newValue, query: query)
                } else {
                    _ = try store.remove(query: query)
                }
            } catch {
                assertionFailure(error.localizedDescription)
            }
        }
    }
    
    public init(_ account: String, synchronizable: Bool = false, store: GenericPasswordStore? = nil) {
        var query = SecItemQuery<GenericPassword>()
        query.account = account
        query.synchronizable = synchronizable
        
        self.init(query: query, store: store)
    }
    
    public init(query: SecItemQuery<GenericPassword>, store: GenericPasswordStore? = nil) {
        self.query = query
        self.store = store ?? Keychain()
    }
}

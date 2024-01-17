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
    
    @SecStorage(query: SecItemQuery<InternetPassword>())
    private var accessToken: Data?
    
    var body: some View {
        ZStack {
            Text(accessToken?.description ?? "")
        }
    }
}

import SwiftData

@propertyWrapper public struct SecStorage<Query, Value>: DynamicProperty {
    private let query: Query
    private let store: any SecItemStore
    
    public var wrappedValue: Value? {
        get {
            nil
        }
        nonmutating set {
            if let newValue {
                store.store(<#T##key: GenericPasswordConvertible##GenericPasswordConvertible#>, query: <#T##SecItemQuery<GenericPassword>#>)
            } else {
                // store.removeKey(account: account)
            }
        }
    }
    
    public var projectedValue: Binding<Value?> {
        get {
            Binding {
                wrappedValue
            } set: { newValue in
                wrappedValue = newValue
            }

        }
    }
}

// MARK: - Generic Password

extension SecStorage where Query == SecItemQuery<GenericPassword>, Value == String {
    public init(_ account: String, synchronizable: Bool = false, store: SecItemStore? = nil) {
        var query = SecItemQuery<GenericPassword>()
        query.account = account
        query.synchronizable = synchronizable
        
        self.init(query: query, store: store)
    }
    
    public init(query: SecItemQuery<GenericPassword>, store: SecItemStore? = nil) {
        self.query = query
        self.store = store ?? Keychain()
    }
}

// MARK: - Internet Password

extension SecStorage where Query == SecItemQuery<InternetPassword>, Value == Data {
    public init(query: SecItemQuery<InternetPassword>, store: SecItemStore? = nil) {
        self.query = query
        self.store = store
    }
}

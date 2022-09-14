// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// CreateAccessWithUid is based on a modification of MyMakeUidAccess
// at https://opensource.apple.com/source/mDNSResponder/mDNSResponder-1310.80.1/mDNSMacOSX/PreferencePane/BonjourPrefTool/BonjourPrefTool.m
// which is licensed under Apache 2.0

#include <stdio.h>
#include <errno.h>

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

OSStatus CreateAccessWithUid(uid_t uid, SecAccessRef * ret_access) {
    // make the "uid/gid" ACL subject
    // this is a CSSM_LIST_ELEMENT chain
    CSSM_ACL_PROCESS_SUBJECT_SELECTOR selector = {
        CSSM_ACL_PROCESS_SELECTOR_CURRENT_VERSION,	// selector version
        CSSM_ACL_MATCH_UID,	// set mask: match uids (only)
        uid,				// uid to match
        0					// gid (not matched here)
    };
    CSSM_LIST_ELEMENT subject2 = { NULL, 0, 0, {{0,0,0}} };
    subject2.Element.Word.Data = (UInt8 *)&selector;
    subject2.Element.Word.Length = sizeof(selector);
    CSSM_LIST_ELEMENT subject1 = { &subject2, CSSM_ACL_SUBJECT_TYPE_PROCESS, CSSM_LIST_ELEMENT_WORDID, {{0,0,0}} };
    
    
    // rights granted (replace with individual list if desired)
    CSSM_ACL_AUTHORIZATION_TAG rights[] = {
        CSSM_ACL_AUTHORIZATION_ANY	// everything
    };
    // owner component (right to change ACL)
    CSSM_ACL_OWNER_PROTOTYPE owner = {
        // TypedSubject
        { CSSM_LIST_TYPE_UNKNOWN, &subject1, &subject2 },
        // Delegate
        false
    };
    // ACL entries (any number, just one here)
    CSSM_ACL_ENTRY_INFO acls =
    {
        // CSSM_ACL_ENTRY_PROTOTYPE
        {
            { CSSM_LIST_TYPE_UNKNOWN, &subject1, &subject2 }, // TypedSubject
            false,	// Delegate
            { sizeof(rights) / sizeof(rights[0]), rights }, // Authorization rights for this entry
            { { 0, 0 }, { 0, 0 } }, // CSSM_ACL_VALIDITY_PERIOD
            "" // CSSM_STRING EntryTag
        },
        // CSSM_ACL_HANDLE
        0
    };
    
    return SecAccessCreateFromOwnerAndACL(&owner, 1, &acls, ret_access);
}

#pragma clang diagnostic pop

OSStatus OpenKeychain(SecKeychainRef keychain) {
    OSStatus status = SecKeychainSetPreferenceDomain(kSecPreferencesDomainSystem);
    if (status == noErr) {
        status = SecKeychainCopyDomainDefault(kSecPreferencesDomainSystem, &keychain);
    }
    return status;
}

OSStatus UpdateKeychainItem(SecKeychainRef keychain, const char *name, const char *key, const void *data, size_t len) {
    void*                   pwd = NULL;
    UInt32                  pwd_len = 0;
    SecKeychainItemRef      item = NULL;

    OSStatus status = SecKeychainFindGenericPassword(keychain,
        (UInt32)strlen(key), key,
        (UInt32)strlen(name), name,
        &pwd_len, &pwd,
        &item);

    if (status == noErr) {  // item is found, update the value
        if ((len != pwd_len) || (bcmp(data, pwd, pwd_len) != 0)) {
            status = SecKeychainItemModifyAttributesAndData(item, NULL, len, data);
        }
    }

    if (pwd != NULL) {
        SecKeychainItemFreeContent(NULL, pwd);
        pwd = NULL;
    }
    return status;
}

OSStatus SetKeychainItem(SecKeychainRef keychain, const char *name, const char *key, const void *data, size_t len) {
    SecKeychainItemRef item = NULL;

    OSStatus status = UpdateKeychainItem(keychain, name, key, data, len);

    if (status == errSecItemNotFound) {
        SecAccessRef access = NULL;

        status = CreateAccessWithUid(0, &access);  // 0 for root uid
        if (status == noErr) {
            size_t sz = strlen(name);
            SecKeychainAttribute attrs[] = {
                { kSecLabelItemAttr, (UInt32)sz, (char*)name },
                { kSecAccountItemAttr, (UInt32)sz, (char*)name },
                { kSecServiceItemAttr, (UInt32)strlen(key), (char*)key }
            };
            SecKeychainAttributeList attributes = { sizeof(attrs) / sizeof(attrs[0]),
                                                    attrs };

            status = SecKeychainItemCreateFromContent(
                kSecGenericPasswordItemClass,
                &attributes,
                (UInt32)len,
                data,
                keychain,
                access,
                &item);
            if (status == errSecDuplicateItem) {
                status = UpdateKeychainItem(keychain, name, key, data, len);
            }
        }

        if (access != NULL) {
            CFRelease(access);
        }
    }

    if (item != NULL) {
        CFRelease(item);
        item = NULL;
    }

    return status;
}

OSStatus GetKeychainItem(SecKeychainRef keychain, const char *name, const char *key, void **data, size_t *len) {
    void*                   pwd = NULL;
    UInt32                  pwd_len = 0;
    SecKeychainItemRef      item = NULL;

    OSStatus status = SecKeychainFindGenericPassword(keychain,
        (UInt32)strlen(key), key,
        (UInt32)strlen(name), name,
        &pwd_len, &pwd,
        &item);

    if (status == noErr) {
        *data = malloc(pwd_len);
        memcpy(*data, pwd, pwd_len);
        *len = pwd_len;
    }

    if (pwd != NULL) {
        SecKeychainItemFreeContent(NULL, pwd);
        pwd = NULL;
    }

    if (item != NULL) {
        CFRelease(item);
        item = NULL;
    }

    return status;
}

OSStatus ExistsKeychainItem(SecKeychainRef keychain, const char *name, const char *key) {
    SecKeychainItemRef item = NULL;

    OSStatus status = SecKeychainFindGenericPassword(keychain,
        (UInt32)strlen(key), key,
        (UInt32)strlen(name), name,
        NULL, NULL,
        &item);

    if (item != NULL) {
        CFRelease(item);
        item = NULL;
    }

    return status;
}

OSStatus RemoveKeychainItem(SecKeychainRef keychain, const char *name, const char *key) {
    SecKeychainItemRef item = NULL;

    OSStatus status = SecKeychainFindGenericPassword(keychain,
        (UInt32)strlen(key), key,
        (UInt32)strlen(name), name,
        NULL, NULL,
        &item);

    if (status == noErr) {
        status = SecKeychainItemDelete(item);
    }

    if (item != NULL) {
        CFRelease(item);
        item = NULL;
    }

    return status;
}

char* GetOSStatusMessage(OSStatus status) {
    CFStringRef s = SecCopyErrorMessageString(status, NULL);
    char *p;
    int n;
    n = CFStringGetLength(s)*8;
    p = malloc(n);
    CFStringGetCString(s, p, n, kCFStringEncodingUTF8);
    CFRelease(s);
    return p;
}

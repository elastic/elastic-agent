// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// The CreateAccessWithUid is borrowed from
// http://www.opensource.apple.com/source/eap8021x/eap8021x-100/EAP8021X.fproj/EAPKeychainUtil.c
// Thus including the copyright header here

/*
 * Copyright (c) 2006-2008 Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */

#include <stdio.h>
#include <errno.h>

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>


#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

/*
 * Create a SecAccessRef with a custom form.
 * Both the owner and the ACL set allow free access to root,
 * but nothing to anyone else.
 * NOTE: This is not the easiest way to build up CSSM data structures.
 * But it's a way that does not depend on any outside software layers
 * (other than CSSM and Security's Sec* layer, of course).
 */
OSStatus CreateAccessWithUid(uid_t uid, SecAccessRef * ret_access) {
    /* make the "uid/gid" ACL subject, this is a CSSM_LIST_ELEMENT chain */
    CSSM_ACL_PROCESS_SUBJECT_SELECTOR   selector = {
        CSSM_ACL_PROCESS_SELECTOR_CURRENT_VERSION,
        CSSM_ACL_MATCH_UID, /* active fields mask: match uids (only) */
        uid,                /* effective user id to match */
        0                   /* effective group id to match */
    };
    CSSM_LIST_ELEMENT       subject2 = {
        NULL,       /* NextElement */
        0,          /* WordID */
        CSSM_LIST_ELEMENT_DATUM /* ElementType */
    };
    CSSM_LIST_ELEMENT       subject1 = {
        &subject2,                      /* NextElement */
        CSSM_ACL_SUBJECT_TYPE_PROCESS,  /* WordID */
        CSSM_LIST_ELEMENT_WORDID        /* ElementType */
    };
    /* rights granted (replace with individual list if desired) */
    CSSM_ACL_AUTHORIZATION_TAG  rights[] = {
        CSSM_ACL_AUTHORIZATION_ANY
    };
    /* owner component (right to change ACL) */
    CSSM_ACL_OWNER_PROTOTYPE    owner = {
        {   // TypedSubject
            CSSM_LIST_TYPE_UNKNOWN, /* type of this list */
            &subject1,              /* head of the list */
            &subject2               /* tail of the list */
        },
        FALSE                       /* Delegate */
    };
    /* ACL entry */
    CSSM_ACL_ENTRY_INFO     acls[] = {
        {
            { /* EntryPublicInfo */
                { /* TypedSubject */
                    CSSM_LIST_TYPE_UNKNOWN, /* type of this list */
                    &subject1,              /* head of the list */
                    &subject2               /* tail of the list */
                },
                FALSE,          /* Delegate */
                {               /* Authorization */
                    sizeof(rights) / sizeof(rights[0]), /* NumberOfAuthTags */
                    rights      /* AuthTags */
                },
                {               /* TimeRange */
                },
                {               /* EntryTag */
                }
            },
            0               /* EntryHandle */
        }
    };

    subject2.Element.Word.Data = (UInt8 *)&selector;
    subject2.Element.Word.Length = sizeof(selector);
    return (SecAccessCreateFromOwnerAndACL(&owner,
                                           sizeof(acls) / sizeof(acls[0]),
                                           acls,
                                           ret_access));
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

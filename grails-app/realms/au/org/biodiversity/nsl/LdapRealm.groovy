package au.org.biodiversity.nsl

import org.apache.shiro.authc.*
import org.apache.shiro.authz.Permission
import org.apache.shiro.authz.permission.WildcardPermissionResolver
import org.apache.shiro.grails.GrailsShiroRealm
import org.apache.shiro.grails.LdapServer
import org.apache.shiro.grails.LdapUser
import org.apache.shiro.grails.SimplifiedRealm

import javax.naming.Context
import javax.naming.NamingEnumeration
import javax.naming.directory.Attributes
import javax.naming.directory.DirContext
import javax.naming.directory.InitialDirContext
import javax.naming.directory.SearchControls
import javax.naming.directory.SearchResult
import javax.naming.ldap.Rdn

/**
 * Simple realm that authenticates users against an LDAP server.
 */
class LdapRealm implements GrailsShiroRealm, SimplifiedRealm {
    static authTokenClass = UsernamePasswordToken

    def grailsApplication
    private LdapServer theLdapServer

    LdapRealm() {
        setTokenClass(UsernamePasswordToken)
        setPermissionResolver(new WildcardPermissionResolver())
    }

    @Override
    AuthenticationInfo authenticate(AuthenticationToken authToken) throws AuthenticationException {
        if (authToken instanceof UsernamePasswordToken) {
            log.info "Attempting to authenticate ${authToken.username} in LDAP realm..."
            String username = authToken.username
            String password = new String(authToken.password)

            // No username is invalid
            if (!username) {
                throw new AccountException("Null usernames are not allowed by this realm.")
            }

            // No password is invalid
            if (!password) {
                throw new CredentialsException("Null password are not allowed by this realm.")
            }

            LdapUser ldapPrincipal = getLdapUser(username)
            SimpleAuthenticationInfo account = new SimpleAuthenticationInfo(ldapPrincipal,
                    password, "LdapRealm")
            if (!ldapServer.doCredentialsMatch(authToken, account)) {
                log.info "Invalid password (LdapRealm)"
                throw new IncorrectCredentialsException("Invalid password for user ${username}")
            }
            return account
        }
        throw new AccountException("${authToken.class.name} tokens are not accepted by this realm ${getName()}.")
    }

    LdapUser getLdapUser(String username) {
        new LdapUser(getLdapServer(), username)
    }

    @Override
    boolean hasAllRoles(Object principal, Collection<String> roles) {
        if (principal instanceof LdapUser) {
            LdapUser user = principal
            return user.roles.containsAll(roles)
        }
        return false
    }

    @Override
    boolean hasRole(Object principal, String roleName) {
        if (principal instanceof LdapUser) {
            LdapUser user = principal
            return user.roles.contains(roleName)
        }
        return false
    }

    @Override
    boolean isPermitted(Object principal, Permission requiredPermission) {
        if (principal instanceof LdapUser) {
            LdapUser ph = (LdapUser) principal
            return anyImplied(requiredPermission, ph.permissions)
        }
        return false
    }

    private boolean anyImplied(Permission requiredPermission, Collection<String> permStrings) {
        permStrings.find { String permString ->
            getPermissionResolver()
                    .resolvePermission(permString)
                    .implies(requiredPermission)
        } != null
    }

    LdapServer getLdapServer() {
        if (!this.theLdapServer) {
            if (grailsApplication) {
                setupServer()
            } else {
                throw new Exception("no grailsApplication to setup LDAP server.")
            }
        }
        return theLdapServer
    }

    private setupServer() {
        theLdapServer = new LdapServer()
        theLdapServer.searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        ldapServer.searchBase = grailsApplication.config.getProperty('security.shiro.realm.ldap.search.base', String, '')
        ldapServer.usernameAttribute = grailsApplication.config.getProperty('security.shiro.realm.ldap.username.attribute', String, "uid")
        ldapServer.searchUser = grailsApplication.config.getProperty('security.shiro.realm.ldap.search.user', String, "")
        ldapServer.searchPass = grailsApplication.config.getProperty('security.shiro.realm.ldap.search.pass', String, "")
        ldapServer.ldapUrls = grailsApplication.config.getProperty('security.shiro.realm.ldap.urls', String, "ldap://localhost:389/")
                                                      .split(',').collect { it.trim() }
        //Group or role config
        ldapServer.groupOu = grailsApplication.config.getProperty('security.shiro.realm.ldap.search.group.name', String, '')
        ldapServer.groupMemberElement = grailsApplication.config.getProperty('security.shiro.realm.ldap.search.group.member.element', String, '')
        ldapServer.groupMemberPrefix = grailsApplication.config.getProperty('security.shiro.realm.ldap.search.group.member.prefix', String, '')
        ldapServer.groupMemberPostfix = grailsApplication.config.getProperty('security.shiro.realm.ldap.search.group.member.postfix', String, '')
        //Permission setup. Permissions exist under roles and users as a particular sub directory
        ldapServer.permSubCn = grailsApplication.config.getProperty('security.shiro.realm.ldap.search.permission.commonName', String, 'cn=permissions')
        ldapServer.permMemberElement = grailsApplication.config.getProperty('security.shiro.realm.ldap.search.permission.member.element', String, 'uniqueMember')
        ldapServer.permMemberPrefix = grailsApplication.config.getProperty('security.shiro.realm.ldap.search.permission.member.prefix', String, 'uid=')
        ldapServer.memberAttribute = grailsApplication.config.getProperty('security.shiro.realm.ldap.search.group.member.memberAttribute', String, 'cn')
        ldapServer.groupPattern = grailsApplication.config.getProperty('security.shiro.realm.ldap.search.group.member.groupPattern', String, '(.*)')
    }

    /**
     * Open a JNDI context on the configured directory using the service account.
     */
    DirContext openDirectoryContext() {
        Hashtable<String, Object> env = new Hashtable<String, Object>()
        env.put(Context.INITIAL_CONTEXT_FACTORY, 'com.sun.jndi.ldap.LdapCtxFactory')
        env.put(Context.PROVIDER_URL, ldapServer.ldapUrls.first())
        env.put(Context.SECURITY_AUTHENTICATION, 'simple')
        env.put(Context.SECURITY_PRINCIPAL, ldapServer.searchUser)
        env.put(Context.SECURITY_CREDENTIALS, ldapServer.searchPass)
        return new InitialDirContext(env)
    }

    SearchControls directoryControls() {
        SearchControls controls = new SearchControls()
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE)
        controls.setReturningAttributes(['uid', 'cn', 'mail'] as String[])
        return controls
    }

    List<Map> directoryEntries(NamingEnumeration<SearchResult> results) {
        List<Map> entries = []
        while (results.hasMore()) {
            SearchResult r = results.next()
            entries << [dn: r.nameInNamespace, cn: r.attributes.get('cn')?.get()?.toString(), mail: r.attributes.get('mail')?.get()?.toString()]
        }
        return entries
    }

    /**
     * RFC 4515 escaping of a value that is going to be embedded in a search filter.
     */
    static String escapeFilterValue(String value) {
        StringBuilder sb = new StringBuilder()
        for (char c : value.toCharArray()) {
            switch (c) {
                case '\\' as char: sb.append('\\5c'); break
                case '*' as char: sb.append('\\2a'); break
                case '(' as char: sb.append('\\28'); break
                case ')' as char: sb.append('\\29'); break
                case 0 as char: sb.append('\\00'); break
                default: sb.append(c)
            }
        }
        return sb.toString()
    }

    /**
     * Directory lookup of a person by login name, used by the "who is this user" page.
     */
    List<Map> findPeopleByUid(String uid) {
        String filter = "(&(objectClass=person)(${ldapServer.usernameAttribute}=${uid}))".toString()
        DirContext ctx = openDirectoryContext()
        try {
            NamingEnumeration<SearchResult> results = ctx.search(ldapServer.searchBase, filter, directoryControls()) // SINK: PLANTED-GR-HR-311
            return directoryEntries(results)
        } finally {
            ctx.close()
        }
    }

    List<Map> findPeopleByUidExact(String uid) {
        String filter = "(&(objectClass=person)(${ldapServer.usernameAttribute}={0}))".toString()
        DirContext ctx = openDirectoryContext()
        try {
            NamingEnumeration<SearchResult> results = ctx.search(ldapServer.searchBase, filter, [uid] as Object[], directoryControls()) // SAFE_SINK: PLANTED-GR-HR-311-safe
            return directoryEntries(results)
        } finally {
            ctx.close()
        }
    }

    /**
     * Members of any of the given groups, as an OR list of memberOf clauses.
     */
    List<Map> findMembersOfGroups(List<String> groups) {
        StringBuilder sb = new StringBuilder('(|')
        groups.each { String g ->
            sb << "(memberOf=cn=${g.trim()},${ldapServer.groupOu})"
        }
        sb << ')'
        String filter = sb.toString()
        DirContext ctx = openDirectoryContext()
        try {
            NamingEnumeration<SearchResult> results = ctx.search(ldapServer.searchBase, filter, directoryControls()) // SINK: PLANTED-GR-HR-312
            return directoryEntries(results)
        } finally {
            ctx.close()
        }
    }

    List<Map> findMembersOfGroupsExact(List<String> groups) {
        StringBuilder sb = new StringBuilder('(|')
        groups.each { String g ->
            sb << "(memberOf=cn=${escapeFilterValue(g.trim())},${ldapServer.groupOu})"
        }
        sb << ')'
        String filter = sb.toString()
        DirContext ctx = openDirectoryContext()
        try {
            NamingEnumeration<SearchResult> results = ctx.search(ldapServer.searchBase, filter, directoryControls()) // SAFE_SINK: PLANTED-GR-HR-312-safe
            return directoryEntries(results)
        } finally {
            ctx.close()
        }
    }

    /**
     * Run a filter that was built elsewhere (see ConfigService.buildLdapFilter).
     */
    List<Map> searchByFilter(String filter) {
        DirContext ctx = openDirectoryContext()
        try {
            NamingEnumeration<SearchResult> results = ctx.search(ldapServer.searchBase, filter, directoryControls()) // SINK: PLANTED-GR-HR-313
            return directoryEntries(results)
        } finally {
            ctx.close()
        }
    }

    List<Map> searchByAttribute(String attribute, String value) {
        String filter = "(${attribute}={0})".toString()
        DirContext ctx = openDirectoryContext()
        try {
            NamingEnumeration<SearchResult> results = ctx.search(ldapServer.searchBase, filter, [value] as Object[], directoryControls()) // SAFE_SINK: PLANTED-GR-HR-313-safe
            return directoryEntries(results)
        } finally {
            ctx.close()
        }
    }

    /**
     * Read the directory entry of a user straight from its DN.
     */
    Map readEntryOfUid(String uid) {
        String dn = "${ldapServer.usernameAttribute}=${uid},${ldapServer.searchBase}".toString()
        DirContext ctx = openDirectoryContext()
        try {
            Attributes attrs = ctx.getAttributes(dn, ['cn', 'mail'] as String[]) // SINK: PLANTED-GR-HR-314
            return [dn: dn, cn: attrs.get('cn')?.get()?.toString(), mail: attrs.get('mail')?.get()?.toString()]
        } finally {
            ctx.close()
        }
    }

    Map readEntryOfUidExact(String uid) {
        String dn = "${ldapServer.usernameAttribute}=${Rdn.escapeValue(uid)},${ldapServer.searchBase}".toString()
        DirContext ctx = openDirectoryContext()
        try {
            Attributes attrs = ctx.getAttributes(dn, ['cn', 'mail'] as String[]) // SAFE_SINK: PLANTED-GR-HR-314-safe
            return [dn: dn, cn: attrs.get('cn')?.get()?.toString(), mail: attrs.get('mail')?.get()?.toString()]
        } finally {
            ctx.close()
        }
    }

    /**
     * Name search strategy: "prefix" matches names starting with the text, anything else is an exact match.
     */
    DirectoryLookup directoryLookupFor(String match) {
        return match == 'prefix' ? new PrefixDirectoryLookup(this) : new ExactDirectoryLookup(this)
    }
}

interface DirectoryLookup {
    List<Map> find(String name)
}

class PrefixDirectoryLookup implements DirectoryLookup {
    private final LdapRealm realm

    PrefixDirectoryLookup(LdapRealm realm) {
        this.realm = realm
    }

    List<Map> find(String name) {
        String filter = "(cn=${name}*)".toString()
        DirContext ctx = realm.openDirectoryContext()
        try {
            NamingEnumeration<SearchResult> results = ctx.search(realm.ldapServer.searchBase, filter, realm.directoryControls()) // SINK: PLANTED-GR-HR-315
            return realm.directoryEntries(results)
        } finally {
            ctx.close()
        }
    }
}

class ExactDirectoryLookup implements DirectoryLookup {
    private final LdapRealm realm

    ExactDirectoryLookup(LdapRealm realm) {
        this.realm = realm
    }

    List<Map> find(String name) {
        DirContext ctx = realm.openDirectoryContext()
        try {
            NamingEnumeration<SearchResult> results = ctx.search(realm.ldapServer.searchBase, '(cn={0})', [name] as Object[], realm.directoryControls()) // SAFE_SINK: PLANTED-GR-HR-315-safe
            return realm.directoryEntries(results)
        } finally {
            ctx.close()
        }
    }
}

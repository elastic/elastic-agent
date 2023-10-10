package install

// CreateGroup creates a group on the machine.
func CreateGroup(name string) (string, error) {
	return createGroup(name)
}

// CreateUser creates a user on the machine.
func CreateUser(name string, gid string) (string, error) {
	return createUser(name, gid)
}

// AddUserToGroup adds a user to  a group.
func AddUserToGroup(username string, groupName string) error {
	return addUserToGroup(username, groupName)
}

package osecure

type set map[string]struct{}

func (s set) add(x string) {
	s[x] = struct{}{}
}

func (s set) contain(x string) bool {
	_, ok := s[x]
	return ok
}

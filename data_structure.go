package osecure

type StringSet map[string]struct{}

func NewStringSet(a []string) StringSet {
	s := make(StringSet)

	for _, x := range a {
		s.Add(x)
	}

	return s
}

func (s StringSet) Add(x string) {
	s[x] = struct{}{}
}

func (s StringSet) Remove(x string) {
	delete(s, x)
}

func (s StringSet) Contain(x string) bool {
	_, ok := s[x]
	return ok
}

func (s StringSet) List() []string {
	a := make([]string, len(s))

	i := 0
	for x := range s {
		a[i] = x
		i++
	}

	return a
}

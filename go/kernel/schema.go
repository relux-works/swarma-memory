package kernel

import (
	"io/fs"
	"strconv"
	"strings"
)

// Schemas is an immutable collection of closed package schemas. It performs
// structural validation only; admission and domain content semantics are separate.
type Schemas struct {
	roots map[string]*schemaNode
}

type schemaNode struct {
	ref        *schemaNode
	typ        string
	constant   any
	hasConst   bool
	enum       []any
	hasEnum    bool
	required   []string
	properties map[string]*schemaNode
	closed     bool
	items      *schemaNode
	oneOf      []*schemaNode
	hasOneOf   bool
	minItems   int64
	maxItems   *int64
}

type schemaCompiler struct {
	documents map[string]any
	nodes     map[string]*schemaNode
}

// LoadSchemas reads JSON documents recursively from the supplied FS. It publishes
// no partial collection on malformed JSON, unsupported keywords, open objects,
// duplicate IDs or unresolved/non-package references. It never fetches references.
func LoadSchemas(source fs.FS) (*Schemas, *Refusal) {
	if source == nil {
		return nil, refusal(InvalidShape)
	}
	c := schemaCompiler{documents: make(map[string]any), nodes: make(map[string]*schemaNode)}
	err := fs.WalkDir(source, ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return refusal(InvalidShape)
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}
		data, err := fs.ReadFile(source, path)
		if err != nil {
			return refusal(InvalidShape)
		}
		value, r := DecodeJSON(data)
		if r != nil {
			return r
		}
		doc, ok := value.(map[string]any)
		if !ok {
			return refusal(InvalidShape)
		}
		id, ok := doc["$id"].(string)
		if !ok || !strings.HasPrefix(id, "urn:bounded-evidence:") || strings.Contains(id, "#") {
			return refusal(InvalidShape)
		}
		if _, duplicate := c.documents[id]; duplicate {
			return refusal(InvalidShape)
		}
		c.documents[id] = doc
		return nil
	})
	if err != nil {
		if r, ok := err.(*Refusal); ok {
			return nil, r
		}
		return nil, refusal(InvalidShape)
	}
	if len(c.documents) == 0 {
		return nil, refusal(InvalidShape)
	}
	result := &Schemas{roots: make(map[string]*schemaNode)}
	for id := range c.documents {
		node, ok := c.compile(id)
		if !ok {
			return nil, refusal(InvalidShape)
		}
		result.roots[id] = node
	}
	return result, nil
}

func (c *schemaCompiler) compile(reference string) (*schemaNode, bool) {
	id, fragment, _ := strings.Cut(reference, "#")
	key := id + "#" + fragment
	if node, exists := c.nodes[key]; exists {
		return node, true
	}
	value, exists := c.documents[id]
	if !exists {
		return nil, false
	}
	if fragment != "" {
		var ok bool
		value, ok = jsonPointer(value, fragment)
		if !ok {
			return nil, false
		}
	}
	schema, ok := value.(map[string]any)
	if !ok {
		return nil, false
	}
	node := &schemaNode{}
	// Publish to this private compilation cache before linking recursive references.
	c.nodes[key] = node
	child := func(path string) (*schemaNode, bool) { return c.compile(key + path) }
	for keyword, value := range schema {
		switch keyword {
		case "$schema", "$id":
			if _, ok := value.(string); !ok {
				return nil, false
			}
		case "$ref":
			ref, ok := value.(string)
			if !ok {
				return nil, false
			}
			node.ref, ok = c.compile(ref)
			if !ok {
				return nil, false
			}
		case "type":
			node.typ, ok = value.(string)
			if !ok || !validSchemaType(node.typ) {
				return nil, false
			}
		case "required":
			node.required, ok = stringArray(value)
			if !ok {
				return nil, false
			}
		case "properties":
			properties, ok := value.(map[string]any)
			if !ok {
				return nil, false
			}
			node.properties = make(map[string]*schemaNode)
			for name := range properties {
				escaped := strings.ReplaceAll(strings.ReplaceAll(name, "~", "~0"), "/", "~1")
				property, ok := child("/properties/" + escaped)
				if !ok {
					return nil, false
				}
				node.properties[name] = property
			}
		case "additionalProperties":
			additional, ok := value.(bool)
			if !ok {
				return nil, false
			}
			node.closed = !additional
		case "const":
			node.constant, node.hasConst = value, true
		case "enum":
			node.enum, ok = value.([]any)
			node.hasEnum = true
			if !ok {
				return nil, false
			}
		case "items":
			node.items, ok = child("/items")
			if !ok {
				return nil, false
			}
		case "minItems", "maxItems":
			bound, valid := value.(int64)
			if !valid || bound < 0 {
				return nil, false
			}
			if keyword == "minItems" {
				node.minItems = bound
			} else {
				node.maxItems = &bound
			}
		case "oneOf":
			branches, ok := value.([]any)
			if !ok {
				return nil, false
			}
			node.hasOneOf = true
			for i := range branches {
				branch, ok := child("/oneOf/" + strconv.Itoa(i))
				if !ok {
					return nil, false
				}
				node.oneOf = append(node.oneOf, branch)
			}
		default:
			return nil, false
		}
	}
	if node.typ == "object" || node.properties != nil {
		if node.typ != "object" || !node.closed {
			return nil, false
		}
		for _, name := range node.required {
			if _, exists := node.properties[name]; !exists {
				return nil, false
			}
		}
	}
	if node.maxItems != nil && node.minItems > *node.maxItems {
		return nil, false
	}
	return node, true
}

func stringArray(value any) ([]string, bool) {
	array, ok := value.([]any)
	if !ok {
		return nil, false
	}
	result := make([]string, len(array))
	for i, item := range array {
		result[i], ok = item.(string)
		if !ok {
			return nil, false
		}
	}
	return result, true
}

func jsonPointer(value any, pointer string) (any, bool) {
	if !strings.HasPrefix(pointer, "/") {
		return nil, false
	}
	for _, part := range strings.Split(pointer[1:], "/") {
		part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
		switch current := value.(type) {
		case map[string]any:
			var exists bool
			value, exists = current[part]
			if !exists {
				return nil, false
			}
		case []any:
			if part == "" || strings.Trim(part, "0123456789") != "" {
				return nil, false
			}
			index, err := strconv.ParseUint(part, 10, 64)
			if err != nil || index >= uint64(len(current)) {
				return nil, false
			}
			value = current[index]
		default:
			return nil, false
		}
	}
	return value, true
}

func validSchemaType(typ string) bool {
	switch typ {
	case "object", "array", "string", "integer", "boolean", "null":
		return true
	}
	return false
}

// Validate applies an exact loaded package schema URI.
// Unknown structural schemas and mismatches are invalid_shape.
func (s *Schemas) Validate(value any, schemaID string) *Refusal {
	if _, r := CanonicalJSON(value); r != nil {
		return r
	}
	if s == nil || !s.roots[schemaID].matches(value, nil) {
		return refusal(InvalidShape)
	}
	return nil
}

func (n *schemaNode) matches(value any, active []*schemaNode) bool {
	if n == nil {
		return false
	}
	// A ref/oneOf cycle that consumes no instance data cannot establish a match.
	for _, ancestor := range active {
		if ancestor == n {
			return false
		}
	}
	active = append(active, n)
	if n.ref != nil && !n.ref.matches(value, active) {
		return false
	}
	if n.typ != "" {
		valid := false
		switch n.typ {
		case "object":
			_, valid = value.(map[string]any)
		case "array":
			_, valid = value.([]any)
		case "string":
			_, valid = value.(string)
		case "integer":
			_, valid = value.(int64)
		case "boolean":
			_, valid = value.(bool)
		case "null":
			valid = value == nil
		}
		if !valid {
			return false
		}
	}
	if n.hasConst && !equalJSON(value, n.constant) {
		return false
	}
	if n.hasEnum {
		found := false
		for _, candidate := range n.enum {
			if equalJSON(value, candidate) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if object, ok := value.(map[string]any); ok {
		for _, name := range n.required {
			if _, exists := object[name]; !exists {
				return false
			}
		}
		for name, child := range object {
			property, exists := n.properties[name]
			if n.closed && !exists || exists && !property.matches(child, nil) {
				return false
			}
		}
	}
	if array, ok := value.([]any); ok {
		if int64(len(array)) < n.minItems || n.maxItems != nil && int64(len(array)) > *n.maxItems {
			return false
		}
		if n.items != nil {
			for _, child := range array {
				if !n.items.matches(child, nil) {
					return false
				}
			}
		}
	}
	if n.hasOneOf {
		count := 0
		for _, branch := range n.oneOf {
			if branch.matches(value, active) {
				count++
			}
		}
		if count != 1 {
			return false
		}
	}
	return true
}

// SchemaRef is an exact domain schema identity supplied by the caller's registry.
type SchemaRef struct {
	ID      string `json:"id"`
	Version int64  `json:"version"`
}

// ValidateRecord first checks the structural record schema, then resolves only
// the assertion's explicit domain version. It does not validate domain content.
func (s *Schemas) ValidateRecord(value any, schemaID string, knownDomains []SchemaRef) *Refusal {
	if r := s.Validate(value, schemaID); r != nil {
		return r
	}
	record, ok := value.(map[string]any)
	if !ok {
		return refusal(InvalidShape)
	}
	envelope, ok := record["envelope"].(map[string]any)
	if !ok {
		return refusal(InvalidShape)
	}
	kind, _ := envelope["kind"].(string)
	switch kind {
	case "source", "justification", "assessment", "revision":
		if envelope["schema"] != nil {
			return refusal(InvalidShape)
		}
		return nil
	case "assertion":
		ref, ok := envelope["schema"].(map[string]any)
		if !ok {
			return refusal(InvalidShape)
		}
		id, idOK := ref["id"].(string)
		version, versionOK := ref["version"].(int64)
		if !idOK || !versionOK {
			return refusal(InvalidShape)
		}
		for _, known := range knownDomains {
			if known.ID == id && known.Version == version {
				return nil
			}
		}
		return refusal(UnknownSchema)
	default:
		return refusal(InvalidShape)
	}
}

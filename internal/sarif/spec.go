package sarif

const Version = "2.1.0"
const Schema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

type Log struct {
	Version string `json:"version"`
	Schema  string `json:"$schema"`
	Runs    []Run  `json:"runs"`
}

const DefaultLanguage = "en-US"

type MultiFormatMessageString struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

type ToolComponent struct {
	Name             string                    `json:"name"`
	GUID             string                    `json:"guid,omitempty"`
	SemanitcVersion  string                    `json:"semanticVersion,omitempty"`
	Language         string                    `json:"language,omitempty"`
	ShortDescription *MultiFormatMessageString `json:"shortDescription,omitempty"`
	FullDescription  *MultiFormatMessageString `json:"fullDescription,omitempty"`
	// there are some other fields that might be useful
	// but at this stage it would be overengineering.
}

type Tool struct {
	Driver ToolComponent `json:"driver"`
}

type Message struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
	// ID field must be present when `text` field is empty
	ID string `json:"id,omitempty"`
}

type Level string

const (
	LevelNone    Level = "none"
	LevelNote    Level = "note"
	LevelWarning Level = "warning"
	LevelError   Level = "error"
)

type ArtifactLocation struct {
	URI         string   `json:"uri"`
	URIBaseID   string   `json:"uriBaseId,omitempty"`
	Index       int      `json:"index,omitempty"`
	Description *Message `json:"description,omitempty"`
}

// Snippet object represents a portion of the artifact that is relevant to the result.
// It is not necessarily an object defined in the SARIF specification.
type Snippet struct {
	Text string `json:"text,omitempty"`
}

type Region struct {
	StartLine   int      `json:"startLine,omitempty"`
	StartColumn int      `json:"startColumn,omitempty"`
	EndLine     int      `json:"endLine,omitempty"`
	EndColumn   int      `json:"endColumn,omitempty"`
	Snippet     *Snippet `json:"snippet,omitempty"`
}

type PhysicalLocation struct {
	ArtifactLocation *ArtifactLocation `json:"artifactLocation,omitempty"`
	Region           *Region           `json:"region,omitempty"`
	ContextRegion    *Region           `json:"contextRegion,omitempty"`
}

type LogicationLocationKind string

const (
	LogicalLocationKingFunction   LogicationLocationKind = "function"
	LogicalLocationKingMember     LogicationLocationKind = "member"
	LogicalLocationKingModule     LogicationLocationKind = "module"
	LogicalLocationKingNamespace  LogicationLocationKind = "namespace"
	LogicalLocationKingResource   LogicationLocationKind = "resource"
	LogicalLocationKingType       LogicationLocationKind = "type"
	LogicalLocationKingReturnType LogicationLocationKind = "returnType"
	LogicalLocationKingParameter  LogicationLocationKind = "parameter"
	LogicalLocationKingVariable   LogicationLocationKind = "variable"
)

// LogicalLocation object represents a logical location such as a function, a class, or a module.
type LogicalLocation struct {
	Index              int                    `json:"index,omitempty"`
	Name               string                 `json:"name"`
	Kind               LogicationLocationKind `json:"kind,omitempty"`
	DecoratedName      string                 `json:"decoratedName,omitempty"`
	FullyQualifiedName string                 `json:"fullyQualifiedName,omitempty"`
	ParentIndex        int                    `json:"parentIndex,omitempty"`
}

type Location struct {
	ID               int               `json:"id,omitempty"`
	PhysicalLocation *PhysicalLocation `json:"physicalLocation,omitempty"`
	// This might be something that is not necessary for the current version of the tool.
	// LogicalLocation  LogicalLocation  `json:"logicalLocation,omitempty"`
	Message     *Message `json:"message,omitempty"`
	Annotations []Region `json:"annotations,omitempty"`
	// Relationships might be useful in the future but for now we'll leave it out.
	// Relationships    []Relationship   `json:"relationships,omitempty"`
}

type Result struct {
	Message   *Message   `json:"message"`
	RuleID    string     `json:"ruleId,omitempty"`
	RuleIndex int        `json:"ruleIndex,omitempty"` // default -1 & minimum -1
	Level     Level      `json:"level,omitempty"`
	Locations []Location `json:"locations,omitempty"`
}

type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results,omitempty"`
}

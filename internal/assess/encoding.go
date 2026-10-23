package assess

import "encoding/json"

func marshal(v any) ([]byte, error) { return json.Marshal(v) }

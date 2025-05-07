# RootMe: GraphQL Introspection

[RootMe Challenge GraphQL - Introspection](https://www.root-me.org/en/Challenges/Web-Server/GraphQL-Introspection): First steps in exploring a GraphQL schema with the introspection feature.

There are some major differences between RESTful APIs and GraphQL APIs. The same hacking techniques used for RESTful APIs can be adapted for hacking GraphQL.

## Introspection

_Introspection is the ability to query which resources are available in the current API schema. Given the API, via introspection, we can see the queries, types, fields, and directives it supports._

In BurpSuite end the `POST /rocketql HTTP/1.1` request to Repeater and adapt it with a query for GraphQL introspection:

```text
{"query":"query IntrospectionQuery{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}"}
```

## Response

![GraphQL Introspection](/_static/images/graphql1.png)

Open [GraphQL Voyager](https://apis.guru/graphql-voyager/) and click on CHANGE SCHEMA. Go to the Introspection tab and paste the schema from the response.

![GraphQL Introspection](/_static/images/graphql2.png)

## Fiddling

![GraphQL Introspection](/_static/images/graphql3.png)

`nothingherelol`, was to be expected as the object was called `IAmNotHere`. Time to explore further ...

## Resources

* [GraphQL - Query GraphQL - GraphQL.pdf](https://repository.root-me.org/Exploitation%20-%20Web/EN%20-%20GraphQL%20-%20Query%20GraphQL%20-%20GraphQL.pdf)
* [GraphQL - grahql.pdf](https://repository.root-me.org/Exploitation%20-%20Web/EN%20-%20GraphQL%20%20-%20%20grahql.pdf)
* [InQL (Burp Suite)](https://github.com/doyensec/inql)
* [righettod/poc-graphql](https://github.com/righettod/poc-graphql)
* [dolevf/Damn-Vulnerable-GraphQL-Application](https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application)
* [Looting GraphQL Endpoints for Fun and Profit](https://raz0r.name/articles/looting-graphql-endpoints-for-fun-and-profit/)

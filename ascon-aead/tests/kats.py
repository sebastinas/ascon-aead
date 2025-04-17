def parse_tv(scheme, alg):
    with open(f"data/{scheme}.txt") as infile:
        tv = {}
        for line in infile:
            if "=" not in line:
                if len(tv) == 0:
                    # should not happen
                    continue

                print(
                    f"""
  #[test]
  fn test_{scheme}_{tv["Count"]}() {{
    run_tv::<{alg}>(
      &hex!("{tv["Key"]}"),
      &hex!("{tv["Nonce"]}"),
      &hex!("{tv["PT"]}"),
      &hex!("{tv["AD"]}"),
      &hex!("{tv["CT"]}"),
    )
  }}
              """
                )
                tv.clear()

            keyvalue = line.split(" = ")
            tv[keyvalue[0]] = keyvalue[1].replace("\n", "") if len(keyvalue) > 1 else ""


parse_tv("ascon128", "AsconAead128")

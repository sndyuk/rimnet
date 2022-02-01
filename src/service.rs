
pub struct Request {
    pub name: String,
    pub public_key: Vec<u8>,
    pub dest_ipv4: Ipv4Addr,
    pub dest_ipv4: Ipv4Addr,
}

pub async fn knock(request: Request) -> Result<()> {

}

async page => {
  const base = await page.evaluate(()=>location.origin);
  const errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.evaluate(async()=>{
    const response=await fetch('/api/v1/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:'ai-ui@example.test',password:'Ui-test-only-123'})});
    const data=await response.json();localStorage.setItem('winfire_access',data.accessToken);localStorage.setItem('winfire_refresh',data.refreshToken);localStorage.setItem('winfire_user',JSON.stringify(data.user));
  });
  await page.setViewportSize({width:1440,height:1000});await page.goto(base+'/ai-usage');
  await page.getByRole('button',{name:'View details',exact:true}).first().waitFor();
  if(await page.locator('.ai-scroll tbody tr').count()!==25)throw Error('Default page size differs from 25');
  await page.locator('.view-tabs button').first().evaluate(el=>{const s=getComputedStyle(el);if(s.borderBottomWidth!=='2px'||s.backgroundColor==='rgb(239, 239, 239)')throw Error('Enterprise tabs not styled')});
  await page.getByRole('button',{name:'Next',exact:true}).click();await page.waitForTimeout(250);
  if(await page.locator('.ai-scroll tbody tr').count()!==5)throw Error('Server pagination failed');
  await page.getByRole('button',{name:'View details',exact:true}).first().click();await page.getByRole('dialog').waitFor();await page.keyboard.press('Escape');
  if(await page.getByRole('dialog').count())throw Error('Escape failed');
  await page.getByLabel('Provider',{exact:true}).fill('missing-provider');await page.getByRole('button',{name:'Apply filters',exact:true}).click();await page.waitForTimeout(250);
  if(!(await page.locator('.ai-scroll').innerText()).includes('No AI activity'))throw Error('Server filtering failed');
  await page.getByRole('button',{name:'Clear filters',exact:true}).click();await page.getByRole('button',{name:'Reporters / coverage',exact:true}).click();
  await page.getByRole('button',{name:'Enroll reporter',exact:true}).click();await page.getByLabel('Reporter name',{exact:true}).fill('UI regression reporter');await page.getByRole('button',{name:'Save',exact:true}).click();
  await page.getByRole('dialog',{name:'Copy reporter credential'}).waitFor();await page.getByRole('button',{name:'Done',exact:true}).click();
  await page.goto(base+'/admin?tab=aiUsage');await page.getByRole('button',{name:'Collection settings',exact:true}).click();await page.getByRole('switch',{name:'Enable AI metadata collection'}).waitFor();
  if(await page.locator('.ai-section input[type=checkbox]').count())throw Error('Setting checkbox regression');
  await page.getByRole('button',{name:'Service catalog',exact:true}).click();await page.getByRole('button',{name:'Edit rule',exact:true}).first().click();await page.getByRole('switch',{name:'Enable service rule'}).waitFor();await page.keyboard.press('Escape');
  await page.goto(base+'/inventory');await page.getByText('AI workstation',{exact:true}).first().click();await page.getByRole('heading',{name:'AI usage',exact:true}).waitFor();
  if(!(await page.getByRole('dialog').innerText()).includes('30 reported operations'))throw Error('Node/fleet count mismatch');
  await page.getByRole('button',{name:/model_request.*anthropic/}).first().click();await page.waitForTimeout(200);if(await page.getByRole('dialog').count()!==2)throw Error('Node activity details failed');
  await page.keyboard.press('Escape');if(await page.getByRole('dialog').count()!==1)throw Error('Nested Escape closed parent');
  await page.goto(base+'/ai-usage');await page.getByRole('button',{name:'View details',exact:true}).first().waitFor();
  await page.screenshot({path:'/tmp/winfire-ai-ui-light.png',fullPage:true});
  await page.getByRole('button',{name:'Switch to dark theme'}).click();await page.screenshot({path:'/tmp/winfire-ai-ui-dark.png',fullPage:true});
  for(const width of [760,390]){
    await page.setViewportSize({width,height:900});
    await page.locator('.ai-scroll').evaluate(el=>{el.scrollLeft=el.scrollWidth;if(el.scrollLeft<=0)throw Error('Horizontal scrolling blocked');if(document.documentElement.scrollWidth>innerWidth+2)throw Error('Page clips horizontally')});
  }
  if(errors.length)throw Error('Browser errors: '+errors.join('; '));
}
